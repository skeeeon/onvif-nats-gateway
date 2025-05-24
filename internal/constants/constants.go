package constants

import "time"

// Application constants
const (
	// Application information
	AppName        = "onvif-nats-gateway"
	AppDescription = "ONVIF to NATS Gateway - Bridge ONVIF events to NATS messaging"
	DefaultVersion = "dev"
)

// Configuration defaults
const (
	// File paths
	DefaultConfigPath       = "config.yaml"
	DefaultDeviceConfigPath = "devices.yaml"
	
	// HTTP server defaults
	DefaultHTTPPort         = 8080
	DefaultHTTPReadTimeout  = 10 * time.Second
	DefaultHTTPWriteTimeout = 10 * time.Second
	
	// NATS defaults
	DefaultNATSURL             = "nats://localhost:4222"
	DefaultNATSConnectionTimeout = 10 * time.Second
	DefaultNATSReconnectWait    = 2 * time.Second
	DefaultNATSMaxReconnects    = 5
	
	// ONVIF defaults
	DefaultONVIFDiscoveryTimeout  = 30 * time.Second
	DefaultONVIFEventPullTimeout  = 60 * time.Second
	DefaultONVIFSubscriptionRenew = 300 * time.Second // 5 minutes
	DefaultONVIFEnableDiscovery   = true
	
	// Event processing defaults
	DefaultEventChannelBuffer = 1000
	DefaultNATSWorkerCount    = 3
	
	// Monitoring defaults
	DefaultDeviceHealthCheckInterval = 30 * time.Second
	DefaultDeviceTimeoutThreshold    = 5 * time.Minute
	
	// Logging defaults
	DefaultLogLevel  = "info"
	DefaultLogFormat = "json"
)

// ONVIF Event Types
const (
	// Motion detection events
	EventTypeMotionAlarm = "tns1:VideoSource/MotionAlarm"
	
	// Audio detection events
	EventTypeAudioDetectedSound = "tns1:AudioAnalytics/Audio/DetectedSound"
	
	// Digital input/output events
	EventTypeDigitalInput  = "tns1:Device/Trigger/DigitalInput"
	EventTypeDigitalOutput = "tns1:Device/Trigger/DigitalOutput"
	
	// Object detection events
	EventTypeObjectDetection = "tns1:VideoAnalytics/ObjectDetection"
	
	// Hardware failure events
	EventTypeStorageFailure = "tns1:Device/HardwareFailure/StorageFailure"
	EventTypeNetworkFailure = "tns1:Device/HardwareFailure/NetworkFailure"
	
	// Tampering events
	EventTypeTampering = "tns1:VideoSource/GlobalSceneChange/ImagingService"
	
	// Recording events
	EventTypeRecordingStart = "tns1:Recording/Recording/Start"
	EventTypeRecordingStop  = "tns1:Recording/Recording/Stop"
)

// NATS Topic patterns
const (
	// Default topic patterns
	DefaultTopicPrefix = "onvif"
	DefaultTestTopic   = "onvif.test"
	
	// Topic separators
	TopicSeparator = "."
)

// HTTP API paths
const (
	// Health and status endpoints
	PathHealth  = "/health"
	PathStatus  = "/status"
	PathVersion = "/version"
	
	// Component endpoints
	PathDevices = "/devices"
	PathNATS    = "/nats"
	
	// Test endpoints
	PathTest = "/test"
)

// HTTP headers
const (
	HeaderContentType = "Content-Type"
	HeaderUserAgent   = "User-Agent"
	
	// Content types
	ContentTypeJSON = "application/json"
	ContentTypeText = "text/plain"
	
	// CORS headers
	HeaderAccessControlAllowOrigin  = "Access-Control-Allow-Origin"
	HeaderAccessControlAllowMethods = "Access-Control-Allow-Methods"
	HeaderAccessControlAllowHeaders = "Access-Control-Allow-Headers"
)

// Status and error messages
const (
	// Status messages
	StatusHealthy  = "healthy"
	StatusDegraded = "degraded"
	StatusRunning  = "running"
	StatusStopping = "stopping"
	StatusStopped  = "stopped"
	
	// Error messages
	ErrMethodNotAllowed    = "Method not allowed"
	ErrInternalServerError = "Internal server error"
	ErrBadRequest          = "Bad request"
	ErrNotFound            = "Not found"
	ErrUnauthorized        = "Unauthorized"
	
	// Success messages
	MsgTestEventPublished = "Test event published successfully"
	MsgServiceStarted     = "Service started successfully"
	MsgServiceStopped     = "Service stopped successfully"
)

// Component names for logging
const (
	ComponentMain         = "main"
	ComponentAPI          = "api"
	ComponentDevice       = "device"
	ComponentNATS         = "nats"
	ComponentConfig       = "config"
	ComponentDiscovery    = "discovery"
	ComponentEventHandler = "event_handler"
)

// Configuration validation patterns
const (
	// URL validation patterns
	HTTPURLPattern  = "^https?://"
	NATSURLPattern  = "^nats://"
	ONVIFURLPattern = "/onvif/"
	
	// Name validation
	MinDeviceNameLength = 1
	MaxDeviceNameLength = 64
	MinTopicLength      = 1
	MaxTopicLength      = 255
)

// Retry and timeout configurations
const (
	// Connection retry settings
	MaxConnectionRetries = 5
	BaseRetryDelay      = 1 * time.Second
	MaxRetryDelay       = 30 * time.Second
	
	// Graceful shutdown timeout
	GracefulShutdownTimeout = 30 * time.Second
	
	// Context timeouts
	DefaultContextTimeout = 10 * time.Second
	LongContextTimeout    = 60 * time.Second
)

// Buffer sizes and limits
const (
	// Channel buffer sizes
	EventChannelBuffer    = 1000
	LogChannelBuffer      = 100
	MetricsChannelBuffer  = 50
	
	// Processing limits
	MaxConcurrentDevices = 100
	MaxEventsPerSecond   = 1000
	MaxEventSize         = 64 * 1024 // 64KB
	
	// Memory limits
	MaxEventBufferSize = 10 * 1024 * 1024 // 10MB
)

// File and directory permissions
const (
	ConfigFileMode = 0644
	LogFileMode    = 0644
	DirMode        = 0755
)

// Environment variable names
const (
	EnvConfigPath       = "ONVIF_CONFIG_PATH"
	EnvDeviceConfigPath = "ONVIF_DEVICE_CONFIG_PATH"
	EnvLogLevel         = "ONVIF_LOG_LEVEL"
	EnvHTTPPort         = "ONVIF_HTTP_PORT"
	EnvNATSURL          = "ONVIF_NATS_URL"
)
