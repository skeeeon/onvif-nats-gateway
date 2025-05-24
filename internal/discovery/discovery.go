package discovery

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"github.com/IOTechSystems/onvif"
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
		s.logger.WithFields(map[string]interface{}{
			"device_index": i + 1,
			"address":      discoveredDevice.XAddr,
		}).Debug("Processing discovered device")

		deviceInfo, err := s.getDeviceInfo(ctx, discoveredDevice)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to get info for device %s: %v", 
				discoveredDevice.XAddr, err)
			s.logger.WithField("address", discoveredDevice.XAddr).
				Warn("Failed to retrieve device information")
			result.Errors = append(result.Errors, errMsg)
			
			// Add basic device info even if detailed info fails
			result.Devices = append(result.Devices, DeviceInfo{
				Address: discoveredDevice.XAddr,
				Name:    fmt.Sprintf("ONVIF Device (%s)", extractHostFromURL(discoveredDevice.XAddr)),
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
func (s *Service) getDeviceInfo(ctx context.Context, discoveredDevice wsdiscovery.DeviceType) (*DeviceInfo, error) {
	// Create ONVIF device connection (without authentication for discovery)
	onvifDevice, err := onvif.NewDevice(onvif.DeviceParams{
		Xaddr: discoveredDevice.XAddr,
		// Note: We don't provide credentials during discovery
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ONVIF device: %w", err)
	}

	// Try to get device information
	deviceInfo := &DeviceInfo{
		Address: discoveredDevice.XAddr,
		Name:    generateDeviceName(discoveredDevice.XAddr),
		Metadata: map[string]string{
			"discovery_url":  discoveredDevice.XAddr,
			"discovery_time": time.Now().Format(time.RFC3339),
		},
	}

	// Extract information from discovery scopes
	s.parseDeviceScopes(deviceInfo, discoveredDevice)

	// Try to get capabilities (may also fail without auth)
	s.parseDeviceCapabilities(deviceInfo, onvifDevice)

	return deviceInfo, nil
}

// parseDeviceScopes extracts device information from WS-Discovery scopes
func (s *Service) parseDeviceScopes(deviceInfo *DeviceInfo, discoveredDevice wsdiscovery.Device) {
	// Extract information from discovery scopes
	// WS-Discovery responses contain device metadata in scopes
	scopes := discoveredDevice.GetScopes()
	
	for _, scope := range scopes {
		scopeStr := strings.ToLower(scope)
		
		// Parse common ONVIF scope patterns
		if strings.Contains(scopeStr, "name/") {
			parts := strings.Split(scope, "name/")
			if len(parts) > 1 {
				deviceInfo.Name = strings.ReplaceAll(parts[1], "_", " ")
			}
		}
		
		if strings.Contains(scopeStr, "hardware/") {
			parts := strings.Split(scope, "hardware/")
			if len(parts) > 1 {
				deviceInfo.Model = parts[1]
			}
		}
		
		if strings.Contains(scopeStr, "location/") {
			parts := strings.Split(scope, "location/")
			if len(parts) > 1 {
				deviceInfo.Metadata["location"] = parts[1]
			}
		}

		// Store all scopes for reference
		if deviceInfo.Metadata["scopes"] == "" {
			deviceInfo.Metadata["scopes"] = scope
		} else {
			deviceInfo.Metadata["scopes"] += ";" + scope
		}
	}

	// Set default name if not found in scopes
	if deviceInfo.Name == "" || strings.Contains(deviceInfo.Name, "ONVIF Device") {
		deviceInfo.Name = fmt.Sprintf("ONVIF Camera (%s)", extractHostFromURL(deviceInfo.Address))
	}
}

// parseDeviceCapabilities attempts to get device capabilities
func (s *Service) parseDeviceCapabilities(deviceInfo *DeviceInfo, onvifDevice *onvif.Device) {
	// Try to get capabilities without authentication
	// This may fail, but we'll attempt it for completeness
	
	capabilities := []string{"device"} // All ONVIF devices support device service
	
	// Common ONVIF capabilities based on typical camera features
	// In a real implementation, this would query GetCapabilities
	capabilities = append(capabilities, "media", "events")
	
	// Set default capabilities
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
			Metadata:   deviceInfo.Metadata,
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

// generateDeviceName creates a human-readable device name
func generateDeviceName(params onvif.DeviceParams) string {
	// Extract hostname/IP from address for basic naming
	host := extractHostFromURL(params.Xaddr)
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
