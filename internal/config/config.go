package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"onvif-nats-gateway/internal/constants"
)

// AppConfig represents the main application configuration
type AppConfig struct {
	NATS    NATSConfig    `yaml:"nats"`
	ONVIF   ONVIFConfig   `yaml:"onvif"`
	HTTP    HTTPConfig    `yaml:"http"`
	Logging LoggingConfig `yaml:"logging"`
}

// DeviceConfig represents the device configuration file
type DeviceConfig struct {
	Devices []Device `yaml:"devices"`
}

// NATSConfig contains NATS connection settings
type NATSConfig struct {
	URL               string        `yaml:"url"`
	Username          string        `yaml:"username"`
	Password          string        `yaml:"password"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	ReconnectWait     time.Duration `yaml:"reconnect_wait"`
	MaxReconnects     int           `yaml:"max_reconnects"`
}

// ONVIFConfig contains ONVIF discovery and event settings
type ONVIFConfig struct {
	DiscoveryTimeout  time.Duration `yaml:"discovery_timeout"`
	EventPullTimeout  time.Duration `yaml:"event_pull_timeout"`
	SubscriptionRenew time.Duration `yaml:"subscription_renew"`
	EnableDiscovery   bool          `yaml:"enable_discovery"`
	WorkerCount       int           `yaml:"worker_count"`
	EventBufferSize   int           `yaml:"event_buffer_size"`
}

// HTTPConfig contains HTTP server settings
type HTTPConfig struct {
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// Device represents configuration for a single ONVIF device
type Device struct {
	Name         string            `yaml:"name"`
	Address      string            `yaml:"address"`
	Username     string            `yaml:"username"`
	Password     string            `yaml:"password"`
	NATSTopic    string            `yaml:"nats_topic"`
	EventTypes   []string          `yaml:"event_types"`
	Metadata     map[string]string `yaml:"metadata"`
	Enabled      bool              `yaml:"enabled"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level     string `yaml:"level"`
	Format    string `yaml:"format"`
	Component string `yaml:"component"`
}

// DiscoveredDevice represents a device found during discovery
type DiscoveredDevice struct {
	Address  string            `yaml:"address"`
	Name     string            `yaml:"name,omitempty"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
}

// LoadAppConfig loads the main application configuration
func LoadAppConfig(path string) (*AppConfig, error) {
	// Set default values
	config := &AppConfig{
		NATS: NATSConfig{
			URL:               constants.DefaultNATSURL,
			ConnectionTimeout: constants.DefaultNATSConnectionTimeout,
			ReconnectWait:     constants.DefaultNATSReconnectWait,
			MaxReconnects:     constants.DefaultNATSMaxReconnects,
		},
		ONVIF: ONVIFConfig{
			DiscoveryTimeout:  constants.DefaultONVIFDiscoveryTimeout,
			EventPullTimeout:  constants.DefaultONVIFEventPullTimeout,
			SubscriptionRenew: constants.DefaultONVIFSubscriptionRenew,
			EnableDiscovery:   constants.DefaultONVIFEnableDiscovery,
			WorkerCount:       constants.DefaultNATSWorkerCount,
			EventBufferSize:   constants.DefaultEventChannelBuffer,
		},
		HTTP: HTTPConfig{
			Port:         constants.DefaultHTTPPort,
			ReadTimeout:  constants.DefaultHTTPReadTimeout,
			WriteTimeout: constants.DefaultHTTPWriteTimeout,
		},
		Logging: LoggingConfig{
			Level:     constants.DefaultLogLevel,
			Format:    constants.DefaultLogFormat,
			Component: constants.ComponentMain,
		},
	}

	return loadConfigFromFile(path, config)
}

// LoadDeviceConfig loads the device configuration
func LoadDeviceConfig(path string) (*DeviceConfig, error) {
	config := &DeviceConfig{
		Devices: []Device{},
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Return empty config if file doesn't exist
		return config, nil
	}

	return loadConfigFromFile(path, config)
}

// SaveDeviceConfig saves the device configuration to file
func SaveDeviceConfig(path string, config *DeviceConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal device config: %w", err)
	}

	if err := os.WriteFile(path, data, constants.ConfigFileMode); err != nil {
		return fmt.Errorf("failed to write device config file: %w", err)
	}

	return nil
}

// CreateDeviceConfigFromDiscovery creates a device config from discovered devices
func CreateDeviceConfigFromDiscovery(devices []DiscoveredDevice, defaultUsername, defaultPassword string) *DeviceConfig {
	config := &DeviceConfig{
		Devices: make([]Device, 0, len(devices)),
	}

	for i, discovered := range devices {
		deviceName := discovered.Name
		if deviceName == "" {
			deviceName = fmt.Sprintf("camera_%02d", i+1)
		}

		// Generate topic from device name
		topic := fmt.Sprintf("%s.%s.events", constants.DefaultTopicPrefix, 
			strings.ToLower(strings.ReplaceAll(deviceName, " ", "_")))

		device := Device{
			Name:       deviceName,
			Address:    discovered.Address,
			Username:   defaultUsername,
			Password:   defaultPassword,
			NATSTopic:  topic,
			EventTypes: getDefaultEventTypes(),
			Metadata:   discovered.Metadata,
			Enabled:    false, // Disabled by default for security
		}

		config.Devices = append(config.Devices, device)
	}

	return config
}

// loadConfigFromFile loads configuration from a YAML file
func loadConfigFromFile[T any](path string, config T) (T, error) {
	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return config, nil // Return default config if file doesn't exist
		}
		return config, fmt.Errorf("failed to access config file: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// Validation functions

// ValidateAppConfig validates the application configuration
func ValidateAppConfig(config *AppConfig) error {
	if config.NATS.URL == "" {
		return fmt.Errorf("NATS URL is required")
	}

	if !strings.HasPrefix(config.NATS.URL, "nats://") {
		return fmt.Errorf("NATS URL must start with 'nats://'")
	}

	if config.ONVIF.DiscoveryTimeout <= 0 {
		return fmt.Errorf("ONVIF discovery timeout must be positive")
	}

	if config.ONVIF.EventPullTimeout <= 0 {
		return fmt.Errorf("ONVIF event pull timeout must be positive")
	}

	if config.ONVIF.WorkerCount <= 0 {
		return fmt.Errorf("ONVIF worker count must be positive")
	}

	if config.HTTP.Port <= 0 || config.HTTP.Port > 65535 {
		return fmt.Errorf("HTTP port must be between 1 and 65535")
	}

	if !isValidLogLevel(config.Logging.Level) {
		return fmt.Errorf("invalid log level: %s", config.Logging.Level)
	}

	return nil
}

// ValidateDeviceConfig validates the device configuration
func ValidateDeviceConfig(config *DeviceConfig) error {
	deviceNames := make(map[string]bool)

	for i, device := range config.Devices {
		if err := ValidateDevice(&device, i); err != nil {
			return err
		}

		// Check for duplicate names
		if deviceNames[device.Name] {
			return fmt.Errorf("duplicate device name: %s", device.Name)
		}
		deviceNames[device.Name] = true
	}

	return nil
}

// ValidateDevice validates a single device configuration
func ValidateDevice(device *Device, index int) error {
	if device.Name == "" {
		return fmt.Errorf("device[%d]: name is required", index)
	}

	if len(device.Name) > constants.MaxDeviceNameLength {
		return fmt.Errorf("device[%d]: name too long (max %d characters)", index, constants.MaxDeviceNameLength)
	}

	if device.Address == "" {
		return fmt.Errorf("device[%d]: address is required", index)
	}

	if !strings.HasPrefix(device.Address, "http://") && !strings.HasPrefix(device.Address, "https://") {
		return fmt.Errorf("device[%d]: address must be a valid HTTP/HTTPS URL", index)
	}

	if device.NATSTopic == "" {
		return fmt.Errorf("device[%d]: NATS topic is required", index)
	}

	if len(device.NATSTopic) > constants.MaxTopicLength {
		return fmt.Errorf("device[%d]: NATS topic too long (max %d characters)", index, constants.MaxTopicLength)
	}

	// Validate event types
	for _, eventType := range device.EventTypes {
		if !isValidEventType(eventType) {
			return fmt.Errorf("device[%d]: unknown event type: %s", index, eventType)
		}
	}

	return nil
}

// Utility functions

// GetDeviceByName returns a device configuration by name
func (dc *DeviceConfig) GetDeviceByName(name string) (*Device, bool) {
	for i := range dc.Devices {
		if dc.Devices[i].Name == name {
			return &dc.Devices[i], true
		}
	}
	return nil, false
}

// GetEnabledDevices returns only enabled devices
func (dc *DeviceConfig) GetEnabledDevices() []Device {
	var enabled []Device
	for _, device := range dc.Devices {
		if device.Enabled {
			enabled = append(enabled, device)
		}
	}
	return enabled
}

// AddDevice adds a new device to the configuration
func (dc *DeviceConfig) AddDevice(device Device) error {
	if err := ValidateDevice(&device, len(dc.Devices)); err != nil {
		return err
	}

	// Check for duplicate names
	if _, exists := dc.GetDeviceByName(device.Name); exists {
		return fmt.Errorf("device with name '%s' already exists", device.Name)
	}

	dc.Devices = append(dc.Devices, device)
	return nil
}

// RemoveDevice removes a device by name
func (dc *DeviceConfig) RemoveDevice(name string) bool {
	for i, device := range dc.Devices {
		if device.Name == name {
			dc.Devices = append(dc.Devices[:i], dc.Devices[i+1:]...)
			return true
		}
	}
	return false
}

// isValidLogLevel checks if the log level is valid
func isValidLogLevel(level string) bool {
	validLevels := []string{"debug", "info", "warn", "warning", "error", "fatal"}
	levelLower := strings.ToLower(level)
	
	for _, valid := range validLevels {
		if levelLower == valid {
			return true
		}
	}
	return false
}

// isValidEventType checks if the event type is known
func isValidEventType(eventType string) bool {
	knownTypes := []string{
		constants.EventTypeMotionAlarm,
		constants.EventTypeAudioDetectedSound,
		constants.EventTypeDigitalInput,
		constants.EventTypeDigitalOutput,
		constants.EventTypeObjectDetection,
		constants.EventTypeStorageFailure,
		constants.EventTypeNetworkFailure,
		constants.EventTypeTampering,
		constants.EventTypeRecordingStart,
		constants.EventTypeRecordingStop,
	}

	for _, known := range knownTypes {
		if eventType == known {
			return true
		}
	}

	// Allow custom event types that start with "tns1:"
	return strings.HasPrefix(eventType, "tns1:")
}

// getDefaultEventTypes returns the default event types for new devices
func getDefaultEventTypes() []string {
	return []string{
		constants.EventTypeMotionAlarm,
		constants.EventTypeAudioDetectedSound,
		constants.EventTypeDigitalInput,
	}
}
