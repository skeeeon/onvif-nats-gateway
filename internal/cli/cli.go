package cli

import (
	"context"
	"flag"
	"fmt"
	"time"

	"onvif-nats-gateway/internal/config"
	"onvif-nats-gateway/internal/constants"
	"onvif-nats-gateway/internal/discovery"
	"onvif-nats-gateway/internal/errors"
	"onvif-nats-gateway/internal/logger"
)

// Command represents a CLI command
type Command struct {
	Name        string
	Description string
	Handler     func(*Context) error
	Flags       []Flag
}

// Flag represents a command-line flag
type Flag struct {
	Name        string
	Description string
	Default     interface{}
	Required    bool
}

// Context contains the command execution context
type Context struct {
	Args    []string
	Flags   map[string]interface{}
	Logger  *logger.Logger
	Config  *config.AppConfig
}

// CLI represents the command-line interface
type CLI struct {
	commands map[string]*Command
	flags    *flag.FlagSet
	logger   *logger.Logger
}

// NewCLI creates a new CLI instance
func NewCLI() *CLI {
	return &CLI{
		commands: make(map[string]*Command),
		flags:    flag.NewFlagSet(constants.AppName, flag.ExitOnError),
	}
}

// Initialize sets up the CLI with all commands and global flags
func (c *CLI) Initialize() {
	// Initialize basic logger for CLI operations
	logger.Initialize(logger.Config{
		Level:  "info",
		Format: "text",
	})
	c.logger = logger.WithComponent("cli")

	// Register commands
	c.registerCommands()
	
	// Setup global flags
	c.setupGlobalFlags()
}

// registerCommands registers all available commands
func (c *CLI) registerCommands() {
	// Discovery command
	c.RegisterCommand(&Command{
		Name:        "discover",
		Description: "Discover ONVIF devices on the network",
		Handler:     c.handleDiscovery,
		Flags: []Flag{
			{Name: "timeout", Description: "Discovery timeout", Default: constants.DefaultONVIFDiscoveryTimeout},
			{Name: "output", Description: "Output file for discovery report", Default: ""},
		},
	})

	// Generate config command
	c.RegisterCommand(&Command{
		Name:        "generate-config",
		Description: "Generate device configuration from discovery",
		Handler:     c.handleGenerateConfig,
		Flags: []Flag{
			{Name: "timeout", Description: "Discovery timeout", Default: constants.DefaultONVIFDiscoveryTimeout},
			{Name: "username", Description: "Default username for devices", Default: "admin", Required: true},
			{Name: "password", Description: "Default password for devices", Default: "", Required: true},
			{Name: "output", Description: "Output file path", Default: constants.DefaultDeviceConfigPath},
		},
	})

	// Version command
	c.RegisterCommand(&Command{
		Name:        "version",
		Description: "Show version information",
		Handler:     c.handleVersion,
	})

	// Validate config command
	c.RegisterCommand(&Command{
		Name:        "validate",
		Description: "Validate configuration files",
		Handler:     c.handleValidateConfig,
		Flags: []Flag{
			{Name: "config", Description: "App config file path", Default: constants.DefaultConfigPath},
			{Name: "devices", Description: "Device config file path", Default: constants.DefaultDeviceConfigPath},
		},
	})
}

// setupGlobalFlags sets up global command-line flags
func (c *CLI) setupGlobalFlags() {
	c.flags.String("config", constants.DefaultConfigPath, "Path to application configuration file")
	c.flags.String("devices", constants.DefaultDeviceConfigPath, "Path to device configuration file")
	c.flags.Int("port", 0, "HTTP port for API server (overrides config)")
	c.flags.String("log-level", "", "Log level (overrides config)")
	c.flags.Bool("help", false, "Show help information")
}

// RegisterCommand registers a new command
func (c *CLI) RegisterCommand(cmd *Command) {
	c.commands[cmd.Name] = cmd
}

// Execute parses command-line arguments and executes the appropriate command
func (c *CLI) Execute(args []string) error {
	if len(args) == 0 {
		return c.showUsage()
	}

	// Handle built-in flags
	for _, arg := range args {
		switch arg {
		case "-h", "--help", "help":
			return c.showUsage()
		case "-v", "--version", "version":
			return c.handleVersion(&Context{})
		}
	}

	// Check if first argument is a command
	cmdName := args[0]
	if cmd, exists := c.commands[cmdName]; exists {
		return c.executeCommand(cmd, args[1:])
	}

	// If no command specified, run the main application
	return nil
}

// executeCommand executes a specific command
func (c *CLI) executeCommand(cmd *Command, args []string) error {
	// Create command-specific flag set
	cmdFlags := flag.NewFlagSet(cmd.Name, flag.ExitOnError)
	
	// Add command-specific flags
	flagValues := make(map[string]interface{})
	for _, f := range cmd.Flags {
		switch v := f.Default.(type) {
		case string:
			flagValues[f.Name] = cmdFlags.String(f.Name, v, f.Description)
		case int:
			flagValues[f.Name] = cmdFlags.Int(f.Name, v, f.Description)
		case bool:
			flagValues[f.Name] = cmdFlags.Bool(f.Name, v, f.Description)
		case time.Duration:
			flagValues[f.Name] = cmdFlags.Duration(f.Name, v, f.Description)
		}
	}

	// Parse command arguments
	if err := cmdFlags.Parse(args); err != nil {
		return errors.NewValidationError("Invalid command arguments", map[string]string{
			"command": cmd.Name,
			"error":   err.Error(),
		})
	}

	// Validate required flags
	for _, f := range cmd.Flags {
		if f.Required {
			switch v := flagValues[f.Name].(type) {
			case *string:
				if *v == "" {
					return errors.NewValidationError(
						fmt.Sprintf("Required flag -%s is missing", f.Name),
						map[string]string{"flag": f.Name},
					)
				}
			}
		}
	}

	// Create context
	ctx := &Context{
		Args:   cmdFlags.Args(),
		Flags:  make(map[string]interface{}),
		Logger: c.logger,
	}

	// Convert flag pointers to values
	for name, ptr := range flagValues {
		switch v := ptr.(type) {
		case *string:
			ctx.Flags[name] = *v
		case *int:
			ctx.Flags[name] = *v
		case *bool:
			ctx.Flags[name] = *v
		case *time.Duration:
			ctx.Flags[name] = *v
		}
	}

	// Execute command
	return cmd.Handler(ctx)
}

// Command handlers

// handleDiscovery handles the discovery command
func (c *CLI) handleDiscovery(ctx *Context) error {
	timeout := ctx.Flags["timeout"].(time.Duration)
	outputFile := ctx.Flags["output"].(string)

	ctx.Logger.Info("Starting ONVIF device discovery")

	// Create discovery service
	discoveryService := discovery.NewService(timeout)

	// Perform discovery
	discoveryCtx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	result, err := discoveryService.DiscoverDevices(discoveryCtx)
	if err != nil {
		return errors.NewDiscoveryError("Failed to discover devices", err)
	}

	// Print results
	c.printDiscoveryResults(result)

	// Save report if output file specified
	if outputFile != "" {
		if err := discoveryService.SaveDiscoveryReport(result, outputFile); err != nil {
			return errors.NewInternalError("Failed to save discovery report", err)
		}
		fmt.Printf("\nDiscovery report saved to: %s\n", outputFile)
	}

	return nil
}

// handleGenerateConfig handles the generate-config command
func (c *CLI) handleGenerateConfig(ctx *Context) error {
	timeout := ctx.Flags["timeout"].(time.Duration)
	username := ctx.Flags["username"].(string)
	password := ctx.Flags["password"].(string)
	outputFile := ctx.Flags["output"].(string)

	if password == "" {
		return errors.NewValidationError("Password is required for config generation", nil)
	}

	ctx.Logger.Info("Generating device configuration from discovery")

	// Create discovery service
	discoveryService := discovery.NewService(timeout)

	// Perform discovery
	discoveryCtx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	result, err := discoveryService.DiscoverDevices(discoveryCtx)
	if err != nil {
		return errors.NewDiscoveryError("Failed to discover devices", err)
	}

	// Generate device configuration
	deviceConfig := discoveryService.GenerateDeviceConfig(result, username, password)

	// Save configuration
	if err := config.SaveDeviceConfig(outputFile, deviceConfig); err != nil {
		return errors.NewInternalError("Failed to save device configuration", err)
	}

	fmt.Printf("Generated device configuration saved to: %s\n", outputFile)
	fmt.Printf("Found %d devices (all disabled by default for security)\n", len(deviceConfig.Devices))
	fmt.Printf("Edit the config file to enable desired devices.\n")

	return nil
}

// handleVersion handles the version command
func (c *CLI) handleVersion(ctx *Context) error {
	fmt.Printf("%s version %s\n", constants.AppName, getVersion())
	fmt.Printf("Build time: %s\n", getBuildTime())
	fmt.Printf("Go version: %s\n", getGoVersion())
	return nil
}

// handleValidateConfig handles the validate command
func (c *CLI) handleValidateConfig(ctx *Context) error {
	appConfigPath := ctx.Flags["config"].(string)
	deviceConfigPath := ctx.Flags["devices"].(string)

	ctx.Logger.Info("Validating configuration files")

	// Validate app config
	appConfig, err := config.LoadAppConfig(appConfigPath)
	if err != nil {
		return errors.NewConfigError("Failed to load app configuration", err)
	}

	if err := config.ValidateAppConfig(appConfig); err != nil {
		return errors.NewConfigValidationError("Invalid app configuration", err.Error())
	}

	// Validate device config
	deviceConfig, err := config.LoadDeviceConfig(deviceConfigPath)
	if err != nil {
		return errors.NewConfigError("Failed to load device configuration", err)
	}

	if err := config.ValidateDeviceConfig(deviceConfig); err != nil {
		return errors.NewConfigValidationError("Invalid device configuration", err.Error())
	}

	fmt.Printf("✓ App configuration is valid (%s)\n", appConfigPath)
	fmt.Printf("✓ Device configuration is valid (%s)\n", deviceConfigPath)
	fmt.Printf("✓ Found %d configured devices (%d enabled)\n", 
		len(deviceConfig.Devices), len(deviceConfig.GetEnabledDevices()))

	return nil
}

// showUsage displays usage information
func (c *CLI) showUsage() error {
	fmt.Printf("%s - %s\n\n", constants.AppName, constants.AppDescription)
	fmt.Printf("Usage:\n")
	fmt.Printf("  %s [command] [options]\n\n", constants.AppName)
	
	fmt.Printf("Commands:\n")
	for name, cmd := range c.commands {
		fmt.Printf("  %-15s %s\n", name, cmd.Description)
	}
	
	fmt.Printf("\nGlobal Options:\n")
	fmt.Printf("  -config string    Path to app configuration file (default: %s)\n", constants.DefaultConfigPath)
	fmt.Printf("  -devices string   Path to device configuration file (default: %s)\n", constants.DefaultDeviceConfigPath)
	fmt.Printf("  -port int         HTTP port for API server (overrides config)\n")
	fmt.Printf("  -log-level string Log level (overrides config)\n")
	fmt.Printf("  -help             Show this help message\n")
	fmt.Printf("  -version          Show version information\n")
	
	fmt.Printf("\nExamples:\n")
	fmt.Printf("  %s discover                                    # Discover ONVIF devices\n", constants.AppName)
	fmt.Printf("  %s generate-config -username admin -password pass  # Generate device config\n", constants.AppName)
	fmt.Printf("  %s validate                                    # Validate configuration\n", constants.AppName)
	fmt.Printf("  %s -config app.yaml -devices devices.yaml     # Run with custom configs\n", constants.AppName)
	
	return nil
}

// printDiscoveryResults prints the discovery results in a formatted way
func (c *CLI) printDiscoveryResults(result *discovery.DiscoveryResult) {
	fmt.Printf("\nONVIF Device Discovery Results\n")
	fmt.Printf("==============================\n")
	fmt.Printf("Total devices found: %d\n", result.Total)
	fmt.Printf("Discovery duration: %v\n", result.Duration)
	fmt.Printf("Errors encountered: %d\n\n", len(result.Errors))

	for i, device := range result.Devices {
		fmt.Printf("Device %d:\n", i+1)
		fmt.Printf("  Name:         %s\n", device.Name)
		fmt.Printf("  Address:      %s\n", device.Address)
		fmt.Printf("  Manufacturer: %s\n", device.Manufacturer)
		fmt.Printf("  Model:        %s\n", device.Model)
		fmt.Printf("  Serial:       %s\n", device.Serial)
		fmt.Printf("  Firmware:     %s\n", device.Firmware)
		fmt.Printf("  Capabilities: %v\n", device.Capabilities)
		if len(device.Metadata) > 0 {
			fmt.Printf("  Metadata:\n")
			for k, v := range device.Metadata {
				fmt.Printf("    %s: %s\n", k, v)
			}
		}
		fmt.Printf("\n")
	}

	if len(result.Errors) > 0 {
		fmt.Printf("Errors:\n")
		for _, errMsg := range result.Errors {
			fmt.Printf("  • %s\n", errMsg)
		}
		fmt.Printf("\n")
	}
}

// Version information (can be set via build flags)
var (
	version   = constants.DefaultVersion
	buildTime = "unknown"
	goVersion = "unknown"
)

func getVersion() string   { return version }
func getBuildTime() string { return buildTime }
func getGoVersion() string { return goVersion }
