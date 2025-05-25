package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"onvif-nats-gateway/internal/api"
	"onvif-nats-gateway/internal/cli"
	"onvif-nats-gateway/internal/config"
	"onvif-nats-gateway/internal/constants"
	"onvif-nats-gateway/internal/device"
	"onvif-nats-gateway/internal/errors"
	"onvif-nats-gateway/internal/logger"
	"onvif-nats-gateway/internal/nats"
)

// Version information (set during build)
var (
	version   = constants.DefaultVersion
	buildTime = "unknown"
	goVersion = "unknown"
)

// Application represents the main application
type Application struct {
	appConfig     *config.AppConfig
	deviceConfig  *config.DeviceConfig
	deviceManager *device.Manager
	natsClient    *nats.Client
	apiServer     *api.Server
	eventChan     chan *device.EventData
	logger        *logger.Logger
}

func main() {
	// Create and initialize CLI
	cliHandler := cli.NewCLI()
	cliHandler.Initialize()

	// Check if this is a CLI command (not the main application)
	if len(os.Args) > 1 {
		// Try to execute as CLI command first
		handled, err := cliHandler.Execute(os.Args[1:])
		if err != nil {
			if appErr, ok := err.(*errors.AppError); ok {
				fmt.Fprintf(os.Stderr, "Error: %s\n", appErr.Message)
				if appErr.Details != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", appErr.Details)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			os.Exit(1)
		}
		
		// If a CLI command was handled, exit successfully
		if handled {
			return
		}
	}

	// Parse command line flags for normal application run
	var (
		configPath       = flag.String("config", constants.DefaultConfigPath, "Path to application configuration file")
		deviceConfigPath = flag.String("devices", constants.DefaultDeviceConfigPath, "Path to device configuration file")
		httpPort         = flag.Int("port", 0, "HTTP port for API server (overrides config)")
		logLevel         = flag.String("log-level", "", "Log level (overrides config)")
		showVersion      = flag.Bool("version", false, "Show version information")
		showHelp         = flag.Bool("help", false, "Show help information")
	)
	flag.Parse()

	// Handle version flag
	if *showVersion {
		fmt.Printf("%s version %s\n", constants.AppName, version)
		fmt.Printf("Build time: %s\n", buildTime)
		fmt.Printf("Go version: %s\n", goVersion)
		return
	}

	// Handle help flag
	if *showHelp {
		flag.Usage()
		return
	}

	// Run main application
	if err := runApplication(*configPath, *deviceConfigPath, *httpPort, *logLevel); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			fmt.Fprintf(os.Stderr, "Fatal error: %s\n", appErr.Message)
			if appErr.Details != "" {
				fmt.Fprintf(os.Stderr, "Details: %s\n", appErr.Details)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Fatal error: %v\n", err)
		}
		os.Exit(1)
	}
}

// runApplication runs the main application
func runApplication(configPath, deviceConfigPath string, httpPort int, logLevel string) error {
	// Load application configuration
	appCfg, err := loadAppConfig(configPath, httpPort, logLevel)
	if err != nil {
		return err
	}

	// Initialize logger
	if err := initializeLogger(appCfg); err != nil {
		return errors.NewConfigError("Failed to initialize logger", err)
	}

	log := logger.WithComponent(constants.ComponentMain)
	log.WithFields(map[string]interface{}{
		"version":    version,
		"build_time": buildTime,
		"go_version": goVersion,
	}).Info("Starting ONVIF-NATS Gateway")

	// Load device configuration
	deviceCfg, err := loadDeviceConfig(deviceConfigPath)
	if err != nil {
		return err
	}

	// Create and start application
	app, err := NewApplication(appCfg, deviceCfg)
	if err != nil {
		return errors.NewInternalError("Failed to create application", err)
	}

	if err := app.Start(); err != nil {
		return errors.NewInternalError("Failed to start application", err)
	}

	// Setup graceful shutdown
	setupGracefulShutdown(app, log)

	log.Info("ONVIF-NATS Gateway started successfully")
	log.WithField("port", getHTTPPort(appCfg, httpPort)).Info("API server available")

	// Wait for shutdown
	<-make(chan struct{})
	return nil
}

// loadAppConfig loads and validates the application configuration
func loadAppConfig(configPath string, httpPort int, logLevel string) (*config.AppConfig, error) {
	appCfg, err := config.LoadAppConfig(configPath)
	if err != nil {
		return nil, errors.NewConfigError("Failed to load app configuration", err)
	}

	// Apply command line overrides
	if httpPort > 0 {
		appCfg.HTTP.Port = httpPort
	}
	if logLevel != "" {
		appCfg.Logging.Level = logLevel
	}

	// Apply environment variable overrides
	applyEnvironmentOverrides(appCfg)

	// Validate configuration
	if err := config.ValidateAppConfig(appCfg); err != nil {
		return nil, errors.NewConfigValidationError("Invalid app configuration", err.Error())
	}

	return appCfg, nil
}

// loadDeviceConfig loads and validates the device configuration
func loadDeviceConfig(deviceConfigPath string) (*config.DeviceConfig, error) {
	deviceCfg, err := config.LoadDeviceConfig(deviceConfigPath)
	if err != nil {
		return nil, errors.NewConfigError("Failed to load device configuration", err)
	}

	if err := config.ValidateDeviceConfig(deviceCfg); err != nil {
		return nil, errors.NewConfigValidationError("Invalid device configuration", err.Error())
	}

	return deviceCfg, nil
}

// initializeLogger initializes the global logger
func initializeLogger(appCfg *config.AppConfig) error {
	loggerConfig := logger.Config{
		Level:     appCfg.Logging.Level,
		Format:    appCfg.Logging.Format,
		Component: appCfg.Logging.Component,
		LogFile:   appCfg.Logging.LogFile,
	}

	return logger.Initialize(loggerConfig)
}

// applyEnvironmentOverrides applies environment variable overrides
func applyEnvironmentOverrides(appCfg *config.AppConfig) {
	if natsURL := os.Getenv(constants.EnvNATSURL); natsURL != "" {
		appCfg.NATS.URL = natsURL
	}
	if logLevel := os.Getenv(constants.EnvLogLevel); logLevel != "" {
		appCfg.Logging.Level = logLevel
	}
	if httpPort := os.Getenv(constants.EnvHTTPPort); httpPort != "" {
		if port := parseIntFromEnv(httpPort); port > 0 {
			appCfg.HTTP.Port = port
		}
	}
}

// NewApplication creates a new application instance
func NewApplication(appCfg *config.AppConfig, deviceCfg *config.DeviceConfig) (*Application, error) {
	log := logger.WithComponent(constants.ComponentMain)

	// Create event channel
	eventChan := make(chan *device.EventData, appCfg.ONVIF.EventBufferSize)

	// Create NATS client
	natsClient := nats.NewClient(&appCfg.NATS, eventChan)

	// Create device manager
	deviceManager := device.NewManager(appCfg, deviceCfg, eventChan)

	// Create API server
	apiConfig := api.Config{
		Port:         appCfg.HTTP.Port,
		ReadTimeout:  appCfg.HTTP.ReadTimeout,
		WriteTimeout: appCfg.HTTP.WriteTimeout,
	}
	apiServer := api.NewServer(apiConfig, deviceManager, natsClient)

	app := &Application{
		appConfig:     appCfg,
		deviceConfig:  deviceCfg,
		deviceManager: deviceManager,
		natsClient:    natsClient,
		apiServer:     apiServer,
		eventChan:     eventChan,
		logger:        log,
	}

	return app, nil
}

// Start starts all application components
func (app *Application) Start() error {
	app.logger.Info("Starting application components")

	// Connect to NATS
	if err := app.natsClient.Connect(); err != nil {
		return errors.NewNATSError(errors.ErrorTypeNATSConnection, "Failed to connect to NATS", err)
	}

	// Start NATS client
	if err := app.natsClient.Start(); err != nil {
		return errors.NewNATSError(errors.ErrorTypeNATSConnection, "Failed to start NATS client", err)
	}

	// Start device manager
	if err := app.deviceManager.Start(); err != nil {
		return errors.NewInternalError("Failed to start device manager", err)
	}

	// Start API server
	if err := app.apiServer.Start(); err != nil {
		return errors.NewInternalError("Failed to start API server", err)
	}

	return nil
}

// Stop gracefully stops all application components
func (app *Application) Stop() {
	if app.logger != nil {
		app.logger.Info("Stopping application components")
	}

	// Stop API server first to prevent new requests
	if app.apiServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), constants.GracefulShutdownTimeout)
		defer cancel()
		
		if err := app.apiServer.Stop(ctx); err != nil && app.logger != nil {
			app.logger.WithField("error", err.Error()).Error("Failed to stop API server gracefully")
		}
	}

	// Stop device manager to prevent new events
	if app.deviceManager != nil {
		app.deviceManager.Stop()
	}

	// Close event channel to signal NATS workers to stop
	if app.eventChan != nil {
		close(app.eventChan)
		app.eventChan = nil
	}

	// Stop NATS client last to ensure all events are published
	if app.natsClient != nil {
		app.natsClient.Stop()
	}

	// Close log file
	logger.Close()

	if app.logger != nil {
		app.logger.Info("Application stopped successfully")
	}
}

// setupGracefulShutdown sets up graceful shutdown handling
func setupGracefulShutdown(app *Application, log *logger.Logger) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.WithField("signal", sig.String()).Info("Shutdown signal received")
		
		// Graceful shutdown with timeout
		shutdownComplete := make(chan struct{})
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.WithField("panic", r).Error("Panic during shutdown")
				}
				close(shutdownComplete)
			}()
			app.Stop()
		}()

		select {
		case <-shutdownComplete:
			log.Info("Graceful shutdown completed")
		case <-time.After(constants.GracefulShutdownTimeout):
			log.Error("Graceful shutdown timeout exceeded, forcing exit")
		}
		
		os.Exit(0)
	}()
}

// Utility functions

// getHTTPPort gets the HTTP port from config or override
func getHTTPPort(appCfg *config.AppConfig, override int) int {
	if override > 0 {
		return override
	}
	return appCfg.HTTP.Port
}

// parseIntFromEnv parses an integer from environment variable
func parseIntFromEnv(value string) int {
	if value == "" {
		return 0
	}
	var result int
	fmt.Sscanf(value, "%d", &result)
	return result
}
