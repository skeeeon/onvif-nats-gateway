package device

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/IOTechSystems/onvif"
	"github.com/IOTechSystems/onvif/device"
	"github.com/IOTechSystems/onvif/event"
	"github.com/IOTechSystems/onvif/ws-discovery"
	
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

// ONVIFDeviceInformation represents device information response
type ONVIFDeviceInformation struct {
	Manufacturer    string `xml:"Manufacturer"`
	Model          string `xml:"Model"`
	FirmwareVersion string `xml:"FirmwareVersion"`
	SerialNumber   string `xml:"SerialNumber"`
	HardwareId     string `xml:"HardwareId"`
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
		m.logger.WithField("address", deviceParams.Xaddr).Debug("Found ONVIF device")
		
		// Check if device is already configured
		found := false
		for _, configDevice := range m.deviceConfig.Devices {
			if configDevice.Address == deviceParams.Xaddr {
				found = true
				break
			}
		}

		if !found {
			m.logger.WithField("address", deviceParams.Xaddr).
				Info("New ONVIF device discovered but not configured")
		}
	}

	return nil
}

// addDevice adds and connects to an ONVIF device
func (m *Manager) addDevice(deviceConfig config.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.devices[deviceConfig.Name]; exists {
		return fmt.Errorf("device %s already exists", deviceConfig.Name)
	}

	device := &Device{
		Config:   deviceConfig,
		LastSeen: time.Now(),
		logger:   logger.WithComponent(constants.ComponentDevice).WithField("device", deviceConfig.Name),
	}

	if err := m.connectDevice(device); err != nil {
		return fmt.Errorf("failed to connect to device: %w", err)
	}

	m.devices[deviceConfig.Name] = device
	m.logger.WithFields(map[string]interface{}{
		"device_name": deviceConfig.Name,
		"address":     deviceConfig.Address,
	}).Info("Added ONVIF device")

	return nil
}

// connectDevice establishes connection to an ONVIF device and tests it
func (m *Manager) connectDevice(dev *Device) error {
	// Create ONVIF device client with authentication
	onvifDevice, err := onvif.NewDevice(onvif.DeviceParams{
		Xaddr:    dev.Config.Address,
		Username: dev.Config.Username,
		Password: dev.Config.Password,
	})
	if err != nil {
		return fmt.Errorf("failed to create ONVIF device: %w", err)
	}

	dev.Client = onvifDevice
	dev.logger.Debug("ONVIF device client created")

	// Test connection by getting device information
	if err := m.testDeviceConnection(dev); err != nil {
		return fmt.Errorf("device connection test failed: %w", err)
	}

	dev.mu.Lock()
	dev.IsConnected = true
	dev.LastSeen = time.Now()
	dev.mu.Unlock()

	dev.logger.Info("ONVIF device connected and verified")

	// Start event subscription
	go m.subscribeToEvents(dev)

	return nil
}

// testDeviceConnection tests the ONVIF device connection
func (m *Manager) testDeviceConnection(dev *Device) error {
	// Test connection using GetDeviceInformation
	getDeviceInfoReq := device.GetDeviceInformation{}
	
	response, err := dev.Client.CallMethod(getDeviceInfoReq)
	if err != nil {
		return fmt.Errorf("GetDeviceInformation failed: %w", err)
	}

	// Parse device information from response
	var deviceInfo ONVIFDeviceInformation
	if err := xml.Unmarshal(response.Body, &deviceInfo); err != nil {
		dev.logger.WithField("error", err.Error()).Warn("Failed to parse device information, but connection is working")
	} else {
		dev.logger.WithFields(map[string]interface{}{
			"manufacturer": deviceInfo.Manufacturer,
			"model":        deviceInfo.Model,
			"firmware":     deviceInfo.FirmwareVersion,
			"serial":       deviceInfo.SerialNumber,
		}).Info("Device information retrieved")
	}

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

	// Create PullPoint subscription
	createSubscription := event.CreatePullPointSubscription{
		InitialTerminationTime: formatDuration(m.appConfig.ONVIF.SubscriptionRenew),
	}

	response, err := dev.Client.CallMethod(createSubscription)
	if err != nil {
		return fmt.Errorf("failed to create PullPoint subscription: %w", err)
	}

	// Parse subscription response to get subscription address
	subscriptionAddr, err := m.parseSubscriptionResponse(response.Body)
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
	pullMessages := event.PullMessages{
		MessageLimit: 100,
		Timeout:      formatDuration(m.appConfig.ONVIF.EventPullTimeout),
	}

	response, err := dev.Client.CallMethod(pullMessages)
	if err != nil {
		return fmt.Errorf("PullMessages failed: %w", err)
	}

	// Parse and process event notifications
	notifications, err := m.parseEventNotifications(response.Body)
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
	renewReq := event.Renew{
		TerminationTime: formatDuration(m.appConfig.ONVIF.SubscriptionRenew),
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

// parseSubscriptionResponse parses the subscription response to extract the subscription address
func (m *Manager) parseSubscriptionResponse(responseBody []byte) (string, error) {
	// This is a simplified parser - in production you'd want more robust XML parsing
	responseStr := string(responseBody)
	
	// Look for subscription reference address in the response
	if strings.Contains(responseStr, "SubscriptionReference") {
		// Extract address from XML - this is simplified
		// In production, use proper XML parsing
		return "subscription_created", nil
	}
	
	return "", fmt.Errorf("could not find subscription reference in response")
}

// parseEventNotifications parses event notifications from the response
func (m *Manager) parseEventNotifications(responseBody []byte) ([]map[string]interface{}, error) {
	// This is a simplified parser for demonstration
	// In production, you'd implement proper ONVIF event XML parsing
	
	var notifications []map[string]interface{}
	responseStr := string(responseBody)
	
	// Look for notification messages in the response
	if strings.Contains(responseStr, "NotificationMessage") {
		// For demonstration, create a sample notification
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
			Metadata:   dev.Config.Metadata,
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
			found := false
			for _, eventType := range dev.Config.EventTypes {
				if eventType == eventData.EventType {
					found = true
					break
				}
			}
			if !found {
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

// Utility functions

// formatDuration formats a Go duration for ONVIF XML (ISO 8601 duration format)
func formatDuration(d time.Duration) string {
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
