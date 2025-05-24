package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"onvif-nats-gateway/internal/logger"
	"onvif-nats-gateway/internal/nats"
)

// Server represents the HTTP API server
type Server struct {
	server        *http.Server
	deviceManager DeviceManagerInterface
	natsClient    NATSClientInterface
	logger        *logger.Logger
	startTime     time.Time
}

// DeviceManagerInterface defines the interface for device manager
type DeviceManagerInterface interface {
	GetDeviceStatus() map[string]bool
}

// NATSClientInterface defines the interface for NATS client
type NATSClientInterface interface {
	IsConnected() bool
	GetConnectionStatus() map[string]interface{}
	GetPublishStats() nats.PublishStats
	PublishEventDirect(topic string, data interface{}) error
}

// Config represents server configuration
type Config struct {
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// NewServer creates a new HTTP API server
func NewServer(cfg Config, deviceManager DeviceManagerInterface, natsClient NATSClientInterface) *Server {
	server := &Server{
		deviceManager: deviceManager,
		natsClient:    natsClient,
		logger:        logger.WithComponent("api"),
		startTime:     time.Now(),
	}

	mux := http.NewServeMux()
	server.setupRoutes(mux)

	server.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      server.loggingMiddleware(server.corsMiddleware(mux)),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return server
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes(mux *http.ServeMux) {
	// Health and status endpoints
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)
	
	// Component-specific endpoints
	mux.HandleFunc("/devices", s.handleDevices)
	mux.HandleFunc("/nats", s.handleNATSStatus)
	
	// Testing endpoints
	mux.HandleFunc("/test", s.handleTestEvent)
	
	// Info endpoints
	mux.HandleFunc("/version", s.handleVersion)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	s.logger.Infof("Starting HTTP server on %s", s.server.Addr)
	
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.WithField("error", err.Error()).Error("HTTP server error")
		}
	}()

	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping HTTP server")
	
	return s.server.Shutdown(ctx)
}

// Middleware functions

// loggingMiddleware logs all HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer wrapper to capture status code
		wrapper := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapper, r)
		
		duration := time.Since(start)
		
		s.logger.WithFields(map[string]interface{}{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status_code": wrapper.statusCode,
			"duration_ms": duration.Milliseconds(),
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.Header.Get("User-Agent"),
		}).Info("HTTP request")
	})
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// Response types

// StatusResponse represents the application status response
type StatusResponse struct {
	Status       string                 `json:"status"`
	Uptime       string                 `json:"uptime"`
	UptimeMs     int64                  `json:"uptime_ms"`
	Devices      map[string]bool        `json:"devices"`
	NATS         map[string]interface{} `json:"nats"`
	PublishStats nats.PublishStats      `json:"publish_stats"`
	Timestamp    time.Time              `json:"timestamp"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
	NATSHealthy bool      `json:"nats_healthy"`
	Uptime      string    `json:"uptime"`
}

// VersionResponse represents version information
type VersionResponse struct {
	Version   string    `json:"version"`
	BuildTime string    `json:"build_time"`
	GoVersion string    `json:"go_version"`
	Timestamp time.Time `json:"timestamp"`
}

// TestEventResponse represents test event response
type TestEventResponse struct {
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Topic     string    `json:"topic"`
	Timestamp time.Time `json:"timestamp"`
}

// Handler functions

// handleHealth returns a simple health check
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uptime := time.Since(s.startTime)
	natsHealthy := s.natsClient.IsConnected()
	
	status := "healthy"
	if !natsHealthy {
		status = "degraded"
	}

	response := HealthResponse{
		Status:      status,
		Timestamp:   time.Now(),
		NATSHealthy: natsHealthy,
		Uptime:      uptime.String(),
	}

	s.writeJSON(w, response, http.StatusOK)
}

// handleStatus returns the overall application status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uptime := time.Since(s.startTime)
	
	response := StatusResponse{
		Status:       "running",
		Uptime:       uptime.String(),
		UptimeMs:     uptime.Milliseconds(),
		Devices:      s.deviceManager.GetDeviceStatus(),
		NATS:         s.natsClient.GetConnectionStatus(),
		PublishStats: s.natsClient.GetPublishStats(),
		Timestamp:    time.Now(),
	}

	s.writeJSON(w, response, http.StatusOK)
}

// handleDevices returns device status information
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	deviceStatus := s.deviceManager.GetDeviceStatus()
	s.writeJSON(w, deviceStatus, http.StatusOK)
}

// handleNATSStatus returns NATS connection status
func (s *Server) handleNATSStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	natsStatus := s.natsClient.GetConnectionStatus()
	publishStats := s.natsClient.GetPublishStats()
	
	response := map[string]interface{}{
		"connection": natsStatus,
		"stats":      publishStats,
		"timestamp":  time.Now(),
	}

	s.writeJSON(w, response, http.StatusOK)
}

// handleTestEvent publishes a test event to NATS
func (s *Server) handleTestEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get topic from query parameter
	topic := r.URL.Query().Get("topic")
	if topic == "" {
		topic = "onvif.test"
	}

	// Create test event
	testEvent := map[string]interface{}{
		"type":      "test_event",
		"timestamp": time.Now(),
		"message":   "This is a test event from ONVIF-NATS Gateway",
		"source":    "http_api",
		"version":   "1.0",
	}

	// Publish test event
	if err := s.natsClient.PublishEventDirect(topic, testEvent); err != nil {
		s.logger.WithFields(map[string]interface{}{
			"topic": topic,
			"error": err.Error(),
		}).Error("Failed to publish test event")
		
		s.writeError(w, fmt.Sprintf("Failed to publish test event: %v", err), http.StatusInternalServerError)
		return
	}

	response := TestEventResponse{
		Status:    "success",
		Message:   "Test event published successfully",
		Topic:     topic,
		Timestamp: time.Now(),
	}

	s.logger.WithField("topic", topic).Info("Test event published successfully")
	s.writeJSON(w, response, http.StatusOK)
}

// handleVersion returns version information
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := VersionResponse{
		Version:   getVersion(),
		BuildTime: getBuildTime(),
		GoVersion: getGoVersion(),
		Timestamp: time.Now(),
	}

	s.writeJSON(w, response, http.StatusOK)
}

// Utility functions

// writeJSON writes a JSON response
func (s *Server) writeJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.WithField("error", err.Error()).Error("Failed to encode JSON response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// writeError writes an error response
func (s *Server) writeError(w http.ResponseWriter, message string, statusCode int) {
	errorResponse := map[string]interface{}{
		"error":     message,
		"status":    statusCode,
		"timestamp": time.Now(),
	}
	
	s.writeJSON(w, errorResponse, statusCode)
}

// responseWriterWrapper wraps http.ResponseWriter to capture status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Version information (can be set via build flags)
var (
	version   = "dev"
	buildTime = "unknown"
	goVersion = "unknown"
)

func getVersion() string   { return version }
func getBuildTime() string { return buildTime }
func getGoVersion() string { return goVersion }
