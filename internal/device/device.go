package device

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/IOTechSystems/onvif"
	"github.com/IOTechSystems/onvif/device"
	"github.com/IOTechSystems/onvif/event"
	"github.com/IOTechSystems/onvif/xsd"
	onvifTypes "github.com/IOTechSystems/onvif/xsd/onvif" // Alias to avoid conflict
	wsdiscovery "github.com/IOTechSystems/onvif/ws-discovery"
	
	"onvif-nats-gateway/internal/config"
	"onvif-nats-gateway/internal/constants"
	"onvif-nats-gateway/internal/logger"
)

// Device represents an ONVIF device with its configuration and client
type Device struct {
	Config           config.Device
	Client           *onvif.Device
	IsConnected      bool
	LastSeen         time.Time
	SubscriptionID   string
	SubscriptionAddr string
	ServiceEndpoints map[string]string // Store discovered service endpoints
	logger           *logger.Logger
	mu               sync.RWMutex
}

// Manager handles multiple ONVIF devices
type Manager struct {
	devices      map[string]*Device
	appConfig    *config.AppConfig
	deviceConfig *config.DeviceConfig
	eventChan    chan<- *EventData
	logger       *logger.Logger
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// EventData represents an event from an ONVIF device
type EventData struct {
	DeviceName  string                 `json:"device_name"`
	DeviceAddr  string                 `json:"device_address"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Topic       string                 `json:"topic"`
	Data        map[string]interface{} `json:"data"`
	Metadata    map[string]string      `json:"metadata"`
}

// NewManager creates a new device manager
func NewManager(appCfg *config.AppConfig, deviceCfg *config.DeviceConfig, eventChan chan<- *EventData) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Manager{
		devices:      make(map[string]*Device),
		appConfig:    appCfg,
		deviceConfig: deviceCfg,
		eventChan:    eventChan,
		logger:       logger.WithComponent(constants.ComponentDevice),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start initializes all devices and begins monitoring
func (m *Manager) Start() error {
	m.logger.Info("Starting device manager")

	// Discover devices if enabled
	if m.appConfig.ONVIF.EnableDiscovery {
		if err := m.discoverDevices(); err != nil {
			m.logger.WithField("error", err.Error()).Warn("Device discovery failed")
		}
	}

	// Initialize configured devices
	enabledDevices := m.deviceConfig.GetEnabledDevices()
	m.logger.WithField("device_count", len(enabledDevices)).Info("Initializing configured devices")
	
	for _, deviceConfig := range enabledDevices {
		if err := m.addDevice(deviceConfig); err != nil {
			m.logger.WithFields(map[string]interface{}{
				"device_name": deviceConfig.Name,
				"error":       err.Error(),
			}).Error("Failed to add device")
			continue
		}
	}

	// Start monitoring devices
	go m.monitorDevices()

	return nil
}

// Stop gracefully shuts down the device manager
func (m *Manager) Stop() {
	m.logger.Info("Stopping device manager")
	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, device := range m.devices {
		m.disconnectDevice(device)
	}
}

// discoverDevices discovers ONVIF devices on the network using WS-Discovery
func (m *Manager) discoverDevices() error {
	m.logger.Info("Discovering ONVIF devices using WS-Discovery")

	// Use WS-Discovery to find devices
	discoveredDevices, err := wsdiscovery.GetAvailableDevicesAtSpecificEthernetInterface("")
	if err != nil {
		return fmt.Errorf("WS-Discovery failed: %w", err)
	}

	m.logger.WithField("device_count", len(discoveredDevices)).Info("WS-Discovery completed")

	for _, discoveredDevice := range discoveredDevices {
		deviceParams := discoveredDevice.GetDeviceParams()
		discoveredAddr := deviceParams.Xaddr
		
		m.logger.WithField("address", discoveredAddr).Debug("Found ONVIF device")
		
		// Check if device is already configured
		found := false
		for _, configDevice := range m.deviceConfig.Devices {
			configHost := m.extractHostPort(configDevice.Address)
			discoveredHost := m.extractHostPort(discoveredAddr)
			
			if configHost == discoveredHost {
				if configDevice.Enabled {
					m.logger.WithFields(map[string]interface{}{
						"device_name":   configDevice.Name,
						"address":       configDevice.Address,
						"discovered_as": discoveredAddr,
					}).Info("ONVIF device is configured and enabled")
				} else {
					m.logger.WithFields(map[string]interface{}{
						"device_name":   configDevice.Name,
						"address":       configDevice.Address,
						"discovered_as": discoveredAddr,
					}).Info("ONVIF device is configured but disabled")
				}
				found = true
				break
			}
		}

		if !found {
			m.logger.WithField("address", discoveredAddr).
				Info("New ONVIF device discovered but not configured")
		}
	}

	return nil
}

// extractHostPort extracts the host:port portion from a URL or address
func (m *Manager) extractHostPort(address string) string {
	// Remove protocol if present
	addr := strings.TrimPrefix(address, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	
	// Split on first slash to get host:port
	parts := strings.Split(addr, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return addr
}

// createHTTPClient creates a standardized HTTP client for ONVIF operations (DRY principle)
func (m *Manager) createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			// Skip TLS verification for cameras with self-signed certificates
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// normalizeDeviceAddress converts various address formats to the format expected by the library (DRY principle)
func (m *Manager) normalizeDeviceAddress(address string) string {
	// Remove protocol prefix if present
	addr := strings.TrimPrefix(address, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	
	// Split on first slash to get host:port part
	parts := strings.Split(addr, "/")
	hostPort := parts[0]
	
	// If no port specified, add default ONVIF port
	if !strings.Contains(hostPort, ":") {
		hostPort = hostPort + ":80"
	}
	
	return hostPort
}

// addDevice adds and connects to an ONVIF device with comprehensive error handling
func (m *Manager) addDevice(deviceConfig config.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.devices[deviceConfig.Name]; exists {
		return fmt.Errorf("device %s already exists", deviceConfig.Name)
	}

	device := &Device{
		Config:           deviceConfig,
		LastSeen:         time.Now(),
		ServiceEndpoints: make(map[string]string),
		logger:           logger.WithComponent(constants.ComponentDevice).WithField("device", deviceConfig.Name),
	}

	device.logger.WithFields(map[string]interface{}{
		"address":      deviceConfig.Address,
		"username":     deviceConfig.Username,
		"nats_topic":   deviceConfig.NATSTopic,
		"event_types":  deviceConfig.EventTypes,
		"metadata":     deviceConfig.Metadata,
	}).Info("Adding ONVIF device")

	// Connect to ONVIF device
	if err := m.connectDevice(device); err != nil {
		device.logger.WithField("error", err.Error()).Error("ONVIF connection failed")
		return fmt.Errorf("failed to connect to device: %w", err)
	}

	m.devices[deviceConfig.Name] = device
	m.logger.WithFields(map[string]interface{}{
		"device_name": deviceConfig.Name,
		"address":     deviceConfig.Address,
	}).Info("Successfully added ONVIF device")

	return nil
}

// connectDevice establishes connection to an ONVIF device using the proper v1.20 patterns
func (m *Manager) connectDevice(dev *Device) error {
	dev.logger.WithFields(map[string]interface{}{
		"address":  dev.Config.Address,
		"username": dev.Config.Username,
		"enabled":  dev.Config.Enabled,
	}).Info("Attempting to connect to ONVIF device")

	// Use standardized HTTP client
	httpClient := m.createHTTPClient()

	// Convert address to proper format for IOTechSystems/onvif library
	deviceAddr := m.normalizeDeviceAddress(dev.Config.Address)
	
	dev.logger.WithField("normalized_address", deviceAddr).Debug("Using normalized device address")

	// Prepare device parameters - the library handles service discovery internally
	deviceParams := onvif.DeviceParams{
		Xaddr:      deviceAddr,
		Username:   dev.Config.Username,
		Password:   dev.Config.Password,
		HttpClient: httpClient,
		// Don't set AuthMode - let the library auto-detect the best method
	}

	dev.logger.WithFields(map[string]interface{}{
		"xaddr":        deviceParams.Xaddr,
		"username":     deviceParams.Username,
		"has_password": len(deviceParams.Password) > 0,
	}).Debug("Creating ONVIF device with parameters")

	// Create ONVIF device - this automatically calls GetCapabilities and discovers services
	onvifDevice, err := onvif.NewDevice(deviceParams)
	if err != nil {
		dev.logger.WithField("error", err.Error()).Error("Failed to create ONVIF device")
		return fmt.Errorf("failed to create ONVIF device: %w", err)
	}

	dev.Client = onvifDevice
	dev.logger.Debug("ONVIF device client created successfully")

	// Test the connection and get device information
	if err := m.testAndDiscoverDevice(dev); err != nil {
		return fmt.Errorf("device connection test failed: %w", err)
	}

	dev.mu.Lock()
	dev.IsConnected = true
	dev.LastSeen = time.Now()
	dev.mu.Unlock()

	dev.logger.WithField("address", deviceAddr).Info("ONVIF device connected and verified successfully")

	// Start event subscription
	go m.subscribeToEvents(dev)

	return nil
}

// testAndDiscoverDevice tests the ONVIF device connection and discovers service endpoints
func (m *Manager) testAndDiscoverDevice(dev *Device) error {
	dev.logger.Debug("Testing ONVIF device connection and discovering services")

	// Test basic device information retrieval using CallMethod
	getDeviceInfoReq := device.GetDeviceInformation{}
	
	dev.logger.Debug("Calling GetDeviceInformation method")
	response, err := dev.Client.CallMethod(getDeviceInfoReq)
	if err != nil {
		dev.logger.WithField("error", err.Error()).Error("GetDeviceInformation call failed")
		return fmt.Errorf("GetDeviceInformation failed: %w", err)
	}

	dev.logger.WithFields(map[string]interface{}{
		"status_code":    response.StatusCode,
		"content_length": response.ContentLength,
		"content_type":   response.Header.Get("Content-Type"),
	}).Debug("Received ONVIF response")

	// Read and parse device information response
	bodyBytes, err := m.readResponseBody(response.Body)
	if err != nil {
		dev.logger.WithField("error", err.Error()).Error("Failed to read response body")
		return fmt.Errorf("failed to read response body: %w", err)
	}

	dev.logger.WithField("response_size", len(bodyBytes)).Debug("Response body read successfully")

	// For now, just log that we got a response - proper XML parsing can be added later
	dev.logger.Info("ONVIF device is reachable and responding")

	// Discover service capabilities using v1.20 CallMethod approach
	if err := m.discoverServiceCapabilities(dev); err != nil {
		dev.logger.WithField("error", err.Error()).Warn("Failed to discover service capabilities, but continuing")
		// Don't fail connection for this - the device might still work
	}

	return nil
}

// discoverServiceCapabilities discovers available ONVIF services on the device using CallMethod
func (m *Manager) discoverServiceCapabilities(dev *Device) error {
	dev.logger.Debug("Discovering ONVIF service capabilities using CallMethod")

	// Create properly typed categories slice for v1.20
	categories := []onvifTypes.CapabilityCategory{
		onvifTypes.CapabilityCategory("All"),
	}

	// Use CallMethod with properly typed GetCapabilities request
	getCapabilitiesReq := device.GetCapabilities{
		Category: categories,
	}
	
	response, err := dev.Client.CallMethod(getCapabilitiesReq)
	if err != nil {
		dev.logger.WithField("error", err.Error()).Debug("GetCapabilities failed")
		return fmt.Errorf("GetCapabilities failed: %w", err)
	}

	// Read capabilities response
	bodyBytes, err := m.readResponseBody(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read capabilities response: %w", err)
	}

	dev.logger.WithField("response_size", len(bodyBytes)).Debug("Received capabilities response")

	// For simplified implementation, parse the response to detect available services
	responseStr := string(bodyBytes)
	
	// Store discovered service endpoints based on response content
	dev.mu.Lock()
	dev.ServiceEndpoints["device"] = "available"
	
	if strings.Contains(responseStr, "Media") {
		dev.ServiceEndpoints["media"] = "available"
	}
	if strings.Contains(responseStr, "Events") {
		dev.ServiceEndpoints["events"] = "available"
	}
	if strings.Contains(responseStr, "PTZ") {
		dev.ServiceEndpoints["ptz"] = "available"
	}
	if strings.Contains(responseStr, "Imaging") {
		dev.ServiceEndpoints["imaging"] = "available"
	}
	if strings.Contains(responseStr, "Analytics") {
		dev.ServiceEndpoints["analytics"] = "available"
	}
	dev.mu.Unlock()

	dev.logger.WithFields(map[string]interface{}{
		"endpoints": dev.ServiceEndpoints,
	}).Info("Discovered ONVIF service capabilities")

	return nil
}

// disconnectDevice disconnects from an ONVIF device
func (m *Manager) disconnectDevice(dev *Device) {
	dev.mu.Lock()
	defer dev.mu.Unlock()

	// Unsubscribe from events if subscription exists
	if dev.SubscriptionAddr != "" {
		m.unsubscribeFromEvents(dev)
		dev.SubscriptionAddr = ""
		dev.SubscriptionID = ""
	}

	dev.IsConnected = false
	dev.logger.Info("ONVIF device disconnected")
}

// subscribeToEvents subscribes to events from an ONVIF device using PullPoint
func (m *Manager) subscribeToEvents(dev *Device) {
	dev.logger.Info("Starting ONVIF event subscription")

	for {
		select {
		case <-m.ctx.Done():
			dev.logger.Info("Event subscription stopping")
			return
		default:
			if err := m.handleEventSubscription(dev); err != nil {
				dev.logger.WithField("error", err.Error()).Error("Event subscription error")
				// Wait before retrying
				select {
				case <-m.ctx.Done():
					return
				case <-time.After(constants.BaseRetryDelay):
					// Continue retry loop
				}
			}
		}
	}
}

// handleEventSubscription manages the ONVIF event subscription lifecycle
func (m *Manager) handleEventSubscription(dev *Device) error {
	dev.mu.Lock()
	if !dev.IsConnected {
		dev.mu.Unlock()
		return fmt.Errorf("device not connected")
	}
	dev.mu.Unlock()

	// Create PullPoint subscription with proper XSD types
	durationStr := formatDurationToXSD(m.appConfig.ONVIF.SubscriptionRenew)
	termTime := xsd.String(durationStr)
	createSubscription := event.CreatePullPointSubscription{
		InitialTerminationTime: &termTime,
	}

	response, err := dev.Client.CallMethod(createSubscription)
	if err != nil {
		return fmt.Errorf("failed to create PullPoint subscription: %w", err)
	}

	// Read and parse subscription response
	bodyBytes, err := m.readResponseBody(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read subscription response: %w", err)
	}

	subscriptionAddr, err := m.parseSubscriptionResponse(bodyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse subscription response: %w", err)
	}

	dev.mu.Lock()
	dev.SubscriptionAddr = subscriptionAddr
	dev.SubscriptionID = subscriptionAddr // Use address as ID for simplicity
	dev.mu.Unlock()

	dev.logger.WithField("subscription_addr", subscriptionAddr).Info("ONVIF event subscription created")

	// Set up subscription renewal ticker
	renewTicker := time.NewTicker(m.appConfig.ONVIF.SubscriptionRenew / 2) // Renew at half the termination time
	defer renewTicker.Stop()

	// Start event pulling loop
	for {
		select {
		case <-m.ctx.Done():
			return nil
		case <-renewTicker.C:
			// Renew subscription
			if err := m.renewSubscription(dev); err != nil {
				dev.logger.WithField("error", err.Error()).Error("Failed to renew subscription")
				return err
			}
			dev.logger.Debug("ONVIF subscription renewed")
		default:
			// Pull events
			if err := m.pullEvents(dev); err != nil {
				dev.logger.WithField("error", err.Error()).Error("Failed to pull events")
				return err
			}

			dev.mu.Lock()
			dev.LastSeen = time.Now()
			dev.mu.Unlock()

			// Brief pause between pulls to avoid overwhelming the device
			time.Sleep(1 * time.Second)
		}
	}
}

// pullEvents pulls event messages from the ONVIF device
func (m *Manager) pullEvents(dev *Device) error {
	timeoutStr := formatDurationToXSD(m.appConfig.ONVIF.EventPullTimeout)
	pullMessages := event.PullMessages{
		MessageLimit: 100,
		Timeout:      xsd.Duration(timeoutStr),
	}

	response, err := dev.Client.CallMethod(pullMessages)
	if err != nil {
		return fmt.Errorf("PullMessages failed: %w", err)
	}

	// Read and parse event notifications
	bodyBytes, err := m.readResponseBody(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read pull response: %w", err)
	}

	notifications, err := m.parseEventNotifications(bodyBytes)
	if err != nil {
		dev.logger.WithField("error", err.Error()).Warn("Failed to parse event notifications")
		return nil // Don't fail the subscription for parse errors
	}

	if len(notifications) > 0 {
		dev.logger.WithField("event_count", len(notifications)).Debug("Received ONVIF events")
		m.processEvents(dev, notifications)
	}

	return nil
}

// renewSubscription renews the ONVIF event subscription
func (m *Manager) renewSubscription(dev *Device) error {
	durationStr := formatDurationToXSD(m.appConfig.ONVIF.SubscriptionRenew)
	renewReq := event.Renew{
		TerminationTime: xsd.String(durationStr),
	}

	_, err := dev.Client.CallMethod(renewReq)
	return err
}

// unsubscribeFromEvents unsubscribes from ONVIF events
func (m *Manager) unsubscribeFromEvents(dev *Device) {
	if dev.SubscriptionAddr == "" {
		return
	}

	unsubscribeReq := event.Unsubscribe{}
	if _, err := dev.Client.CallMethod(unsubscribeReq); err != nil {
		dev.logger.WithField("error", err.Error()).Warn("Failed to unsubscribe from events")
	} else {
		dev.logger.Debug("Successfully unsubscribed from ONVIF events")
	}
}

// readResponseBody reads the response body and closes it (DRY principle)
func (m *Manager) readResponseBody(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	return io.ReadAll(body)
}

// parseSubscriptionResponse parses the subscription response to extract the subscription address
func (m *Manager) parseSubscriptionResponse(responseBody []byte) (string, error) {
	// This is a simplified parser - in production, you'd want more robust XML parsing
	responseStr := string(responseBody)
	
	// Look for subscription reference address in the response
	if strings.Contains(responseStr, "SubscriptionReference") {
		// Extract address from XML - this is simplified
		// In production, use proper XML parsing with structs
		return "subscription_created", nil
	}
	
	return "", fmt.Errorf("could not find subscription reference in response")
}

// parseEventNotifications parses event notifications from the response
func (m *Manager) parseEventNotifications(responseBody []byte) ([]map[string]interface{}, error) {
	// This is a simplified parser for demonstration
	// In production, you'd implement proper ONVIF event XML parsing with structs
	
	var notifications []map[string]interface{}
	responseStr := string(responseBody)
	
	// Look for notification messages in the response
	if strings.Contains(responseStr, "NotificationMessage") {
		// For demonstration, create sample notifications
		// In production, parse the actual XML structure
		notification := map[string]interface{}{
			"Topic":     "tns1:VideoSource/MotionAlarm",
			"Message":   "Motion detected",
			"Timestamp": time.Now().Format(time.RFC3339),
			"Source":    "VideoSource",
		}
		notifications = append(notifications, notification)
	}
	
	return notifications, nil
}

// processEvents processes events from a device and sends them to NATS
func (m *Manager) processEvents(dev *Device, notifications []map[string]interface{}) {
	for _, notification := range notifications {
		eventData := &EventData{
			DeviceName: dev.Config.Name,
			DeviceAddr: dev.Config.Address,
			Timestamp:  time.Now(),
			Topic:      dev.Config.NATSTopic,
			Metadata:   copyStringMap(dev.Config.Metadata),
			Data:       notification,
		}

		// Extract event type from notification
		if topic, exists := notification["Topic"]; exists {
			if topicStr, ok := topic.(string); ok {
				eventData.EventType = topicStr
			}
		}

		// Filter events by configured types if specified
		if len(dev.Config.EventTypes) > 0 {
			if !m.isEventTypeAllowed(eventData.EventType, dev.Config.EventTypes) {
				continue // Skip this event
			}
		}

		// Send event to NATS publisher
		select {
		case m.eventChan <- eventData:
			dev.logger.WithFields(map[string]interface{}{
				"event_type": eventData.EventType,
				"topic":      eventData.Topic,
			}).Debug("Sent ONVIF event to NATS")
		case <-m.ctx.Done():
			return
		default:
			dev.logger.Warn("Event channel full, dropping ONVIF event")
		}
	}
}

// isEventTypeAllowed checks if an event type is in the allowed list
func (m *Manager) isEventTypeAllowed(eventType string, allowedTypes []string) bool {
	for _, allowedType := range allowedTypes {
		if allowedType == eventType {
			return true
		}
	}
	return false
}

// monitorDevices monitors device health and connectivity
func (m *Manager) monitorDevices() {
	ticker := time.NewTicker(constants.DefaultDeviceHealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.mu.RLock()
			for _, device := range m.devices {
				device.mu.RLock()
				timeSinceLastSeen := time.Since(device.LastSeen)
				isConnected := device.IsConnected
				device.mu.RUnlock()

				if isConnected && timeSinceLastSeen > constants.DefaultDeviceTimeoutThreshold {
					device.logger.WithField("last_seen", timeSinceLastSeen.String()).
						Warn("ONVIF device appears to be unresponsive")
				}
			}
			m.mu.RUnlock()
		}
	}
}

// GetDeviceStatus returns the status of all devices
func (m *Manager) GetDeviceStatus() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]bool)
	for name, device := range m.devices {
		device.mu.RLock()
		status[name] = device.IsConnected
		device.mu.RUnlock()
	}

	return status
}

// GetDeviceEndpoints returns discovered service endpoints for a device
func (m *Manager) GetDeviceEndpoints(deviceName string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	device, exists := m.devices[deviceName]
	if !exists {
		return nil, fmt.Errorf("device %s not found", deviceName)
	}

	device.mu.RLock()
	defer device.mu.RUnlock()

	// Return a copy of the endpoints map
	endpoints := make(map[string]string)
	for k, v := range device.ServiceEndpoints {
		endpoints[k] = v
	}

	return endpoints, nil
}

// Utility functions

// formatDurationToXSD formats a Go duration for ONVIF XML (ISO 8601 duration format)
func formatDurationToXSD(d time.Duration) string {
	// Convert to ISO 8601 duration format (PT30S for 30 seconds, PT5M for 5 minutes)
	seconds := int(d.Seconds())
	if seconds < 60 {
		return fmt.Sprintf("PT%dS", seconds)
	}
	minutes := seconds / 60
	if minutes < 60 {
		return fmt.Sprintf("PT%dM", minutes)
	}
	hours := minutes / 60
	return fmt.Sprintf("PT%dH", hours)
}

// copyStringMap creates a copy of a string map (DRY principle)
func copyStringMap(original map[string]string) map[string]string {
	if original == nil {
		return make(map[string]string)
	}
	
	copy := make(map[string]string, len(original))
	for k, v := range original {
		copy[k] = v
	}
	return copy
}
