package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
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
	LogFile   string `yaml:"log_file,omitempty"` // Optional log file path
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

	// Validate address format - IOTechSystems/onvif library expects host:port format
	if err := validateDeviceAddress(device.Address); err != nil {
		return fmt.Errorf("device[%d]: %w", index, err)
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

// validateDeviceAddress validates the device address format
// IOTechSystems/onvif library expects host:port format, not full URLs
func validateDeviceAddress(address string) error {
	// Check if it looks like a URL (legacy format that needs fixing)
	if strings.HasPrefix(address, "http://") || strings.HasPrefix(address, "https://") {
		return fmt.Errorf("address should be in host:port format (e.g., 192.168.1.100:80), not a URL. Use 'fix-config' command to convert URLs to the correct format")
	}

	// Validate host:port format
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("address must be in host:port format (e.g., 192.168.1.100:80 or camera.local:8080), got: %s", address)
	}

	// Validate host part (IP address or hostname)
	if host == "" {
		return fmt.Errorf("host part cannot be empty in address: %s", address)
	}

	// Try to parse as IP address
	if ip := net.ParseIP(host); ip == nil {
		// If not an IP, validate as hostname
		if !isValidHostname(host) {
			return fmt.Errorf("invalid hostname or IP address: %s", host)
		}
	}

	// Validate port part
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port number: %s", portStr)
	}

	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got: %d", port)
	}

	return nil
}

// isValidHostname validates a hostname according to RFC standards
func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Hostname cannot start or end with a dot
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}

	// Split into labels and validate each
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if !isValidHostnameLabel(label) {
			return false
		}
	}

	return true
}

// isValidHostnameLabel validates a single hostname label
func isValidHostnameLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}

	// Label cannot start or end with hyphen
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}

	// Label can only contain alphanumeric characters and hyphens
	for _, r := range label {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}

	return true
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

// GetAllDevices returns all devices (enabled and disabled)
func (dc *DeviceConfig) GetAllDevices() []Device {
	return dc.Devices
}

// CountEnabledDevices returns the count of enabled devices
func (dc *DeviceConfig) CountEnabledDevices() int {
	count := 0
	for _, device := range dc.Devices {
		if device.Enabled {
			count++
		}
	}
	return count
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

// EnableDevice enables a device by name
func (dc *DeviceConfig) EnableDevice(name string) bool {
	for i := range dc.Devices {
		if dc.Devices[i].Name == name {
			dc.Devices[i].Enabled = true
			return true
		}
	}
	return false
}

// DisableDevice disables a device by name
func (dc *DeviceConfig) DisableDevice(name string) bool {
	for i := range dc.Devices {
		if dc.Devices[i].Name == name {
			dc.Devices[i].Enabled = false
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
