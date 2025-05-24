package discovery

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"github.com/IOTechSystems/onvif"
	"github.com/IOTechSystems/onvif/device"
	wsdiscovery "github.com/IOTechSystems/onvif/ws-discovery"

	"onvif-nats-gateway/internal/config"
	"onvif-nats-gateway/internal/constants"
	"onvif-nats-gateway/internal/logger"
)

// Service handles ONVIF device discovery
type Service struct {
	logger  *logger.Logger
	timeout time.Duration
}

// DeviceInfo contains information about a discovered device
type DeviceInfo struct {
	Address      string            `json:"address"`
	Name         string            `json:"name"`
	Manufacturer string            `json:"manufacturer"`
	Model        string            `json:"model"`
	Serial       string            `json:"serial"`
	Firmware     string            `json:"firmware"`
	Capabilities []string          `json:"capabilities"`
	Metadata     map[string]string `json:"metadata"`
}

// DiscoveryResult contains the results of device discovery
type DiscoveryResult struct {
	Devices      []DeviceInfo `json:"devices"`
	Total        int          `json:"total"`
	Duration     time.Duration `json:"duration"`
	Errors       []string     `json:"errors,omitempty"`
}

// NewService creates a new discovery service
func NewService(timeout time.Duration) *Service {
	return &Service{
		logger:  logger.WithComponent(constants.ComponentDiscovery),
		timeout: timeout,
	}
}

// DiscoverDevices discovers ONVIF devices on the network using WS-Discovery
func (s *Service) DiscoverDevices(ctx context.Context) (*DiscoveryResult, error) {
	s.logger.Info("Starting ONVIF device discovery")
	startTime := time.Now()
	
	result := &DiscoveryResult{
		Devices: make([]DeviceInfo, 0),
		Errors:  make([]string, 0),
	}

	// Use WS-Discovery to find ONVIF devices on all network interfaces
	s.logger.Debug("Performing WS-Discovery probe")
	discoveredDevices, err := wsdiscovery.GetAvailableDevicesAtSpecificEthernetInterface("")
	if err != nil {
		errMsg := fmt.Sprintf("WS-Discovery failed: %v", err)
		s.logger.Error(errMsg)
		result.Errors = append(result.Errors, errMsg)
		// Continue processing even if discovery fails partially
	}

	s.logger.WithField("discovered_count", len(discoveredDevices)).Info("WS-Discovery completed")

	// Process each discovered device
	for i, discoveredDevice := range discoveredDevices {
		deviceParams := discoveredDevice.GetDeviceParams()
		s.logger.WithFields(map[string]interface{}{
			"device_index": i + 1,
			"address":      deviceParams.Xaddr,
		}).Debug("Processing discovered device")

		deviceInfo, err := s.getDeviceInfo(ctx, discoveredDevice)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to get info for device %s: %v", 
				deviceParams.Xaddr, err)
			s.logger.WithField("address", deviceParams.Xaddr).
				Warn("Failed to retrieve device information")
			result.Errors = append(result.Errors, errMsg)
			
			// Add basic device info even if detailed info fails
			result.Devices = append(result.Devices, DeviceInfo{
				Address: deviceParams.Xaddr,
				Name:    fmt.Sprintf("ONVIF Device (%s)", extractHostFromURL(deviceParams.Xaddr)),
				Metadata: map[string]string{
					"discovery_error": err.Error(),
					"discovery_time":  time.Now().Format(time.RFC3339),
				},
			})
			continue
		}

		result.Devices = append(result.Devices, *deviceInfo)
		
		s.logger.WithFields(map[string]interface{}{
			"address":      deviceInfo.Address,
			"name":         deviceInfo.Name,
			"manufacturer": deviceInfo.Manufacturer,
			"model":        deviceInfo.Model,
		}).Info("Successfully processed ONVIF device")
	}

	result.Total = len(result.Devices)
	result.Duration = time.Since(startTime)

	s.logger.WithFields(map[string]interface{}{
		"total_devices": result.Total,
		"duration_ms":   result.Duration.Milliseconds(),
		"errors":        len(result.Errors),
	}).Info("ONVIF device discovery completed")

	return result, nil
}

// getDeviceInfo retrieves detailed information about a discovered device
func (s *Service) getDeviceInfo(ctx context.Context, discoveredDevice onvif.Device) (*DeviceInfo, error) {
	deviceParams := discoveredDevice.GetDeviceParams()
	
	// Initialize device info with basic information
	deviceInfo := &DeviceInfo{
		Address: deviceParams.Xaddr,
		Name:    generateDeviceName(deviceParams.Xaddr),
		Metadata: map[string]string{
			"discovery_url":  deviceParams.Xaddr,
			"discovery_time": time.Now().Format(time.RFC3339),
		},
	}

	// Try to get device information (this may fail without authentication)
	if err := s.getDeviceInformation(deviceInfo, &discoveredDevice); err != nil {
		s.logger.WithField("address", deviceParams.Xaddr).
			Debug("Could not retrieve device information (likely requires authentication)")
	}

	// Get capabilities information
	s.getDeviceCapabilities(deviceInfo, &discoveredDevice)

	return deviceInfo, nil
}

// getDeviceInformation attempts to retrieve device information
func (s *Service) getDeviceInformation(deviceInfo *DeviceInfo, onvifDevice *onvif.Device) error {
	// Create GetDeviceInformation request
	getDeviceInfoReq := device.GetDeviceInformation{}
	
	// Call the method
	response, err := onvifDevice.CallMethod(getDeviceInfoReq)
	if err != nil {
		return fmt.Errorf("GetDeviceInformation failed: %w", err)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	response.Body.Close()

	// Try to extract information from response
	// Note: This is simplified parsing - in production you'd want more robust XML parsing
	responseStr := string(bodyBytes)
	
	// Extract basic information using simple string parsing
	// In production, use proper XML unmarshaling
	if manufacturer := extractXMLValue(responseStr, "Manufacturer"); manufacturer != "" {
		deviceInfo.Manufacturer = manufacturer
	}
	if model := extractXMLValue(responseStr, "Model"); model != "" {
		deviceInfo.Model = model
	}
	if firmware := extractXMLValue(responseStr, "FirmwareVersion"); firmware != "" {
		deviceInfo.Firmware = firmware
	}
	if serial := extractXMLValue(responseStr, "SerialNumber"); serial != "" {
		deviceInfo.Serial = serial
	}

	// Update device name if we have manufacturer and model
	if deviceInfo.Manufacturer != "" && deviceInfo.Model != "" {
		deviceInfo.Name = fmt.Sprintf("%s %s", deviceInfo.Manufacturer, deviceInfo.Model)
	}

	return nil
}

// getDeviceCapabilities attempts to get device capabilities
func (s *Service) getDeviceCapabilities(deviceInfo *DeviceInfo, onvifDevice *onvif.Device) {
	// Set default capabilities that all ONVIF devices should support
	capabilities := []string{"device"}
	
	// Try to get more detailed capabilities (may fail without auth)
	// For now, we'll set common ONVIF capabilities
	capabilities = append(capabilities, "media", "events")
	
	deviceInfo.Capabilities = capabilities
	deviceInfo.Metadata["capabilities_note"] = "Default capabilities - authentication required for full discovery"
}

// GenerateDeviceConfig creates a device configuration from discovery results
func (s *Service) GenerateDeviceConfig(result *DiscoveryResult, defaultUsername, defaultPassword string) *config.DeviceConfig {
	s.logger.WithField("device_count", len(result.Devices)).Info("Generating device configuration")

	deviceConfig := &config.DeviceConfig{
		Devices: make([]config.Device, 0, len(result.Devices)),
	}

	for i, deviceInfo := range result.Devices {
		device := config.Device{
			Name:       generateUniqueDeviceName(deviceInfo, i),
			Address:    deviceInfo.Address,
			Username:   defaultUsername,
			Password:   defaultPassword,
			NATSTopic:  generateNATSTopic(deviceInfo, i),
			EventTypes: getDefaultEventTypes(deviceInfo),
			Metadata:   copyMetadata(deviceInfo.Metadata),
			Enabled:    false, // Disabled by default for security
		}

		deviceConfig.Devices = append(deviceConfig.Devices, device)
	}

	return deviceConfig
}

// SaveDiscoveryReport saves a discovery report to file
func (s *Service) SaveDiscoveryReport(result *DiscoveryResult, filename string) error {
	s.logger.WithField("filename", filename).Info("Saving discovery report")

	// Convert to YAML format for better readability
	report := struct {
		DiscoveryResult
		GeneratedAt string `yaml:"generated_at"`
		Note        string `yaml:"note"`
	}{
		DiscoveryResult: *result,
		GeneratedAt:     time.Now().Format(time.RFC3339),
		Note:           "Generated by ONVIF-NATS Gateway using WS-Discovery",
	}

	data, err := yaml.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal discovery report: %w", err)
	}

	if err := os.WriteFile(filename, data, constants.ConfigFileMode); err != nil {
		return fmt.Errorf("failed to write discovery report: %w", err)
	}

	return nil
}

// Utility functions

// generateDeviceName creates a human-readable device name from address
func generateDeviceName(address string) string {
	host := extractHostFromURL(address)
	return fmt.Sprintf("ONVIF Camera (%s)", host)
}

// generateUniqueDeviceName creates a unique device name
func generateUniqueDeviceName(deviceInfo DeviceInfo, index int) string {
	if deviceInfo.Name != "" && !strings.Contains(deviceInfo.Name, "Unknown") {
		return sanitizeName(deviceInfo.Name)
	}

	// Generate name based on manufacturer and model
	if deviceInfo.Manufacturer != "" && deviceInfo.Model != "" {
		return fmt.Sprintf("%s_%s_%02d", 
			sanitizeName(deviceInfo.Manufacturer), 
			sanitizeName(deviceInfo.Model), 
			index+1)
	}

	// Fallback to generic name with host
	host := extractHostFromURL(deviceInfo.Address)
	return fmt.Sprintf("camera_%s_%02d", sanitizeName(host), index+1)
}

// generateNATSTopic creates a NATS topic for the device
func generateNATSTopic(deviceInfo DeviceInfo, index int) string {
	deviceName := generateUniqueDeviceName(deviceInfo, index)
	topicName := strings.ToLower(strings.ReplaceAll(deviceName, " ", "_"))
	return fmt.Sprintf("%s.%s.events", constants.DefaultTopicPrefix, topicName)
}

// getDefaultEventTypes returns default event types based on device capabilities
func getDefaultEventTypes(deviceInfo DeviceInfo) []string {
	defaultTypes := []string{
		constants.EventTypeMotionAlarm,
	}

	// Add additional event types based on capabilities
	for _, capability := range deviceInfo.Capabilities {
		switch strings.ToLower(capability) {
		case "audio":
			defaultTypes = append(defaultTypes, constants.EventTypeAudioDetectedSound)
		case "io", "digital_input":
			defaultTypes = append(defaultTypes, constants.EventTypeDigitalInput)
		case "analytics":
			defaultTypes = append(defaultTypes, constants.EventTypeObjectDetection)
		}
	}

	return defaultTypes
}

// extractHostFromURL extracts hostname/IP from URL
func extractHostFromURL(url string) string {
	// Remove protocol if present
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	
	// Split on first slash to get host:port
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		// Split host:port to get just host
		hostPort := parts[0]
		host := strings.Split(hostPort, ":")[0]
		if host != "" {
			return host
		}
	}
	return url
}

// sanitizeName removes invalid characters from names
func sanitizeName(name string) string {
	// Replace spaces and special characters with underscores
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	
	// Remove other special characters
	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		}
	}
	
	cleaned := result.String()
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}

// extractXMLValue extracts a value from XML using simple string parsing
func extractXMLValue(xmlStr, tagName string) string {
	startTag := fmt.Sprintf("<%s>", tagName)
	endTag := fmt.Sprintf("</%s>", tagName)
	
	startIdx := strings.Index(xmlStr, startTag)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(startTag)
	
	endIdx := strings.Index(xmlStr[startIdx:], endTag)
	if endIdx == -1 {
		return ""
	}
	
	return strings.TrimSpace(xmlStr[startIdx : startIdx+endIdx])
}

// copyMetadata creates a copy of metadata map
func copyMetadata(original map[string]string) map[string]string {
	if original == nil {
		return make(map[string]string)
	}
	
	copy := make(map[string]string, len(original))
	for k, v := range original {
		copy[k] = v
	}
	return copy
}
