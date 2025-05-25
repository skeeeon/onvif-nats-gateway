package cli

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/IOTechSystems/onvif"
	"github.com/IOTechSystems/onvif/device"
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
	// Initialize basic logger for CLI operations with more verbose output
	logger.Initialize(logger.Config{
		Level:  "debug", // Use debug level for CLI operations to show discovery progress
		Format: "text",  // Use text format for better CLI readability
	})
	c.logger = logger.WithComponent("cli")

	// Register commands
	c.registerCommands()
	
	// Setup global flags
	c.setupGlobalFlags()
	
	c.logger.Debug("CLI initialized successfully")
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
			{Name: "verbose", Description: "Enable verbose output", Default: false},
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
			{Name: "verbose", Description: "Enable verbose output", Default: false},
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

	// Fix config command
	c.RegisterCommand(&Command{
		Name:        "fix-config",
		Description: "Fix device configuration by normalizing addresses",
		Handler:     c.handleFixConfig,
		Flags: []Flag{
			{Name: "devices", Description: "Device config file path", Default: constants.DefaultDeviceConfigPath},
			{Name: "backup", Description: "Create backup before fixing", Default: true},
		},
	})

	// Enable device command
	c.RegisterCommand(&Command{
		Name:        "enable-device",
		Description: "Enable a device in the configuration",
		Handler:     c.handleEnableDevice,
		Flags: []Flag{
			{Name: "devices", Description: "Device config file path", Default: constants.DefaultDeviceConfigPath},
			{Name: "name", Description: "Device name to enable", Default: "", Required: true},
		},
	})

	// List devices command
	c.RegisterCommand(&Command{
		Name:        "list-devices",
		Description: "List all devices in the configuration",
		Handler:     c.handleListDevices,
		Flags: []Flag{
			{Name: "devices", Description: "Device config file path", Default: constants.DefaultDeviceConfigPath},
		},
	})

	// Test connection command
	c.RegisterCommand(&Command{
		Name:        "test-connection",
		Description: "Test connectivity to a specific device",
		Handler:     c.handleTestConnection,
		Flags: []Flag{
			{Name: "address", Description: "Device ONVIF service URL or host:port", Default: "", Required: true},
			{Name: "username", Description: "Username for authentication", Default: "admin"},
			{Name: "password", Description: "Password for authentication", Default: "", Required: true},
			{Name: "verbose", Description: "Enable verbose output", Default: false},
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
// Returns (handled, error) where handled indicates if a CLI command was processed
func (c *CLI) Execute(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil // No command specified, run main application
	}

	// Handle built-in help and version flags
	for _, arg := range args {
		switch arg {
		case "-h", "--help", "help":
			c.showUsage()
			return true, nil
		case "-v", "--version", "version":
			err := c.handleVersion(&Context{})
			return true, err
		}
	}

	// Check if first argument is a registered command
	cmdName := args[0]
	if cmd, exists := c.commands[cmdName]; exists {
		err := c.executeCommand(cmd, args[1:])
		return true, err // Command was found and executed
	}

	// Command not found - this might be a flag for the main application
	return false, nil
}

// executeCommand executes a specific command
func (c *CLI) executeCommand(cmd *Command, args []string) error {
	// Create command-specific flag set
	cmdFlags := flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
	
	// Capture flag parsing errors
	cmdFlags.Usage = func() {
		fmt.Printf("Usage: %s %s [options]\n\n", constants.AppName, cmd.Name)
		fmt.Printf("%s\n\n", cmd.Description)
		if len(cmd.Flags) > 0 {
			fmt.Printf("Options:\n")
			cmdFlags.PrintDefaults()
		}
	}
	
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
		if err == flag.ErrHelp {
			return nil // Help was shown, exit cleanly
		}
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
						fmt.Sprintf("Required flag -%s is missing or empty", f.Name),
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

	// Debug output for CLI commands
	c.logger.WithFields(map[string]interface{}{
		"command": cmd.Name,
		"flags":   ctx.Flags,
	}).Debug("Executing CLI command")

	// Execute command
	return cmd.Handler(ctx)
}

// Command handlers

// handleDiscovery handles the discovery command
func (c *CLI) handleDiscovery(ctx *Context) error {
	timeout := ctx.Flags["timeout"].(time.Duration)
	outputFile := ctx.Flags["output"].(string)
	verbose := ctx.Flags["verbose"].(bool)

	fmt.Printf("Starting ONVIF device discovery (timeout: %v)...\n", timeout)
	
	if verbose {
		fmt.Printf("Verbose mode enabled - showing detailed discovery process\n")
		// Set logger to debug level for verbose output
		logger.Initialize(logger.Config{
			Level:  "debug",
			Format: "text",
		})
	}
	
	ctx.Logger.Info("Starting ONVIF device discovery")

	// Create discovery service
	discoveryService := discovery.NewService(timeout)

	// Perform discovery
	discoveryCtx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	fmt.Printf("Scanning network for ONVIF devices...\n")
	if verbose {
		fmt.Printf("Using WS-Discovery protocol on UDP port 3702\n")
		fmt.Printf("This may take up to %v depending on network size\n", timeout)
	}

	result, err := discoveryService.DiscoverDevices(discoveryCtx)
	if err != nil {
		fmt.Printf("Discovery failed: %v\n", err)
		return errors.NewDiscoveryError("Failed to discover devices", err)
	}

	// Print results
	c.printDiscoveryResults(result)

	// Save report if output file specified
	if outputFile != "" {
		if err := discoveryService.SaveDiscoveryReport(result, outputFile); err != nil {
			fmt.Printf("Failed to save discovery report: %v\n", err)
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
	verbose := ctx.Flags["verbose"].(bool)

	if password == "" {
		fmt.Printf("Error: Password is required for config generation\n")
		return errors.NewValidationError("Password is required for config generation", nil)
	}

	fmt.Printf("Generating device configuration from discovery...\n")
	fmt.Printf("Default credentials: %s / %s\n", username, "[hidden]")
	fmt.Printf("Discovery timeout: %v\n", timeout)
	
	if verbose {
		fmt.Printf("Verbose mode enabled - showing detailed discovery process\n")
		// Set logger to debug level for verbose output
		logger.Initialize(logger.Config{
			Level:  "debug",
			Format: "text",
		})
	}
	
	ctx.Logger.Info("Generating device configuration from discovery")

	// Create discovery service
	discoveryService := discovery.NewService(timeout)

	// Perform discovery
	fmt.Printf("Discovering ONVIF devices...\n")
	discoveryCtx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	result, err := discoveryService.DiscoverDevices(discoveryCtx)
	if err != nil {
		fmt.Printf("Discovery failed: %v\n", err)
		return errors.NewDiscoveryError("Failed to discover devices", err)
	}

	fmt.Printf("Found %d devices\n", result.Total)

	// Generate device configuration
	fmt.Printf("Generating device configuration...\n")
	deviceConfig := discoveryService.GenerateDeviceConfig(result, username, password)

	// Save configuration
	if err := config.SaveDeviceConfig(outputFile, deviceConfig); err != nil {
		fmt.Printf("Failed to save configuration: %v\n", err)
		return errors.NewInternalError("Failed to save device configuration", err)
	}

	fmt.Printf("\n✓ Generated device configuration saved to: %s\n", outputFile)
	fmt.Printf("✓ Found %d devices (all disabled by default for security)\n", len(deviceConfig.Devices))
	
	// Show summary of generated devices
	if len(deviceConfig.Devices) > 0 {
		fmt.Printf("\nDiscovered devices:\n")
		for i, device := range deviceConfig.Devices {
			fmt.Printf("  %d. %s\n", i+1, device.Name)
			fmt.Printf("     Address: %s\n", device.Address)
			fmt.Printf("     Topic:   %s\n", device.NATSTopic)
		}
		
		fmt.Printf("\nNext steps:\n")
		fmt.Printf("1. Edit %s and set 'enabled: true' for devices you want to monitor\n", outputFile)
		fmt.Printf("2. Verify device addresses are correct (normalized to host:port format)\n")
		fmt.Printf("3. Test connectivity with: %s test-connection -address HOST:PORT -username admin -password PASSWORD\n", constants.AppName)
		fmt.Printf("4. Run the gateway: %s -devices %s\n", constants.AppName, outputFile)
	} else {
		fmt.Printf("\nNo devices found. Try:\n")
		fmt.Printf("• Ensure ONVIF devices are powered on and connected\n")
		fmt.Printf("• Check that ONVIF is enabled on your cameras\n")
		fmt.Printf("• Verify network connectivity\n")
	}

	return nil
}

// handleVersion handles the version command
func (c *CLI) handleVersion(ctx *Context) error {
	fmt.Printf("%s version %s\n", constants.AppName, getVersion())
	fmt.Printf("Build time: %s\n", getBuildTime())
	fmt.Printf("Go version: %s\n", getGoVersion())
	return nil
}

// handleFixConfig handles the fix-config command
func (c *CLI) handleFixConfig(ctx *Context) error {
	deviceConfigPath := ctx.Flags["devices"].(string)
	createBackup := ctx.Flags["backup"].(bool)

	fmt.Printf("Fixing device configuration addresses...\n")
	fmt.Printf("Config file: %s\n", deviceConfigPath)

	// Load device config
	deviceConfig, err := config.LoadDeviceConfig(deviceConfigPath)
	if err != nil {
		fmt.Printf("Failed to load device configuration: %v\n", err)
		return errors.NewConfigError("Failed to load device configuration", err)
	}

	if len(deviceConfig.Devices) == 0 {
		fmt.Printf("No devices found in configuration file.\n")
		return nil
	}

	// Create backup if requested
	if createBackup {
		backupPath := deviceConfigPath + ".backup"
		if err := config.SaveDeviceConfig(backupPath, deviceConfig); err != nil {
			fmt.Printf("Warning: Failed to create backup: %v\n", err)
		} else {
			fmt.Printf("✓ Backup created: %s\n", backupPath)
		}
	}

	// Fix addresses
	fixed := 0
	for i := range deviceConfig.Devices {
		device := &deviceConfig.Devices[i]
		originalAddr := device.Address
		
		// Normalize the address using the new method
		normalizedAddr := c.normalizeAddressForLibrary(originalAddr)
		
		if originalAddr != normalizedAddr {
			fmt.Printf("Fixed device[%d] %s:\n", i, device.Name)
			fmt.Printf("  Old: %s\n", originalAddr)
			fmt.Printf("  New: %s\n", normalizedAddr)
			device.Address = normalizedAddr
			fixed++
		}
	}

	if fixed == 0 {
		fmt.Printf("✓ All device addresses are already properly formatted.\n")
		return nil
	}

	// Save the fixed configuration
	if err := config.SaveDeviceConfig(deviceConfigPath, deviceConfig); err != nil {
		fmt.Printf("Failed to save fixed configuration: %v\n", err)
		return errors.NewInternalError("Failed to save device configuration", err)
	}

	fmt.Printf("\n✓ Fixed %d device addresses\n", fixed)
	fmt.Printf("✓ Configuration saved to: %s\n", deviceConfigPath)
	
	// Validate the fixed configuration
	if err := config.ValidateDeviceConfig(deviceConfig); err != nil {
		fmt.Printf("Warning: Configuration still has validation issues: %v\n", err)
		return nil // Don't fail, just warn
	}
	
	fmt.Printf("✓ Configuration is now valid\n")
	return nil
}

// normalizeAddressForLibrary converts various address formats to the host:port format expected by the IOTechSystems/onvif library
func (c *CLI) normalizeAddressForLibrary(address string) string {
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
func (c *CLI) showUsage() {
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
	fmt.Printf("  %s list-devices                                # List all configured devices\n", constants.AppName)
	fmt.Printf("  %s enable-device -name camera_01               # Enable a specific device\n", constants.AppName)
	fmt.Printf("  %s test-connection -address 192.168.1.100:80 -username admin -password pass  # Test device connectivity\n", constants.AppName)
	fmt.Printf("  %s fix-config                                  # Fix device addresses in config\n", constants.AppName)
	fmt.Printf("  %s validate                                    # Validate configuration\n", constants.AppName)
	fmt.Printf("  %s -config app.yaml -devices devices.yaml     # Run with custom configs\n", constants.AppName)
}

// printDiscoveryResults prints the discovery results in a formatted way
func (c *CLI) printDiscoveryResults(result *discovery.DiscoveryResult) {
	fmt.Printf("\n=== ONVIF Device Discovery Results ===\n")
	fmt.Printf("Total devices found: %d\n", result.Total)
	fmt.Printf("Discovery duration: %v\n", result.Duration)
	
	if len(result.Errors) > 0 {
		fmt.Printf("Errors encountered: %d\n", len(result.Errors))
	}
	
	fmt.Printf("\n")

	if len(result.Devices) == 0 {
		fmt.Printf("No ONVIF devices found on the network.\n")
		fmt.Printf("\nTroubleshooting tips:\n")
		fmt.Printf("• Ensure ONVIF devices are on the same network\n")
		fmt.Printf("• Check if devices have ONVIF enabled\n")
		fmt.Printf("• Verify network connectivity and firewall settings\n")
		fmt.Printf("• Try increasing the discovery timeout\n")
		return
	}

	for i, device := range result.Devices {
		fmt.Printf("Device %d:\n", i+1)
		fmt.Printf("  Name:         %s\n", device.Name)
		fmt.Printf("  Address:      %s\n", device.Address)
		
		if device.Manufacturer != "" {
			fmt.Printf("  Manufacturer: %s\n", device.Manufacturer)
		}
		if device.Model != "" {
			fmt.Printf("  Model:        %s\n", device.Model)
		}
		if device.Serial != "" {
			fmt.Printf("  Serial:       %s\n", device.Serial)
		}
		if device.Firmware != "" {
			fmt.Printf("  Firmware:     %s\n", device.Firmware)
		}
		
		if len(device.Capabilities) > 0 {
			fmt.Printf("  Capabilities: %v\n", device.Capabilities)
		}
		
		if len(device.Metadata) > 0 {
			fmt.Printf("  Metadata:\n")
			for k, v := range device.Metadata {
				if k != "scopes" { // Skip verbose scopes output
					fmt.Printf("    %s: %s\n", k, v)
				}
			}
		}
		fmt.Printf("\n")
	}

	if len(result.Errors) > 0 {
		fmt.Printf("Errors encountered:\n")
		for i, errMsg := range result.Errors {
			fmt.Printf("  %d. %s\n", i+1, errMsg)
		}
		fmt.Printf("\n")
	}
	
	fmt.Printf("Next steps:\n")
	fmt.Printf("• Use 'generate-config' command to create device configuration\n")
	fmt.Printf("• Manually configure devices in devices.yaml\n")
	fmt.Printf("• Test connectivity with 'test-connection' command\n")
}

// handleEnableDevice handles the enable-device command
func (c *CLI) handleEnableDevice(ctx *Context) error {
	deviceConfigPath := ctx.Flags["devices"].(string)
	deviceName := ctx.Flags["name"].(string)

	fmt.Printf("Enabling device '%s' in configuration...\n", deviceName)

	// Load device config
	deviceConfig, err := config.LoadDeviceConfig(deviceConfigPath)
	if err != nil {
		fmt.Printf("Failed to load device configuration: %v\n", err)
		return errors.NewConfigError("Failed to load device configuration", err)
	}

	// Find and enable the device
	found := false
	for i := range deviceConfig.Devices {
		if deviceConfig.Devices[i].Name == deviceName {
			if deviceConfig.Devices[i].Enabled {
				fmt.Printf("Device '%s' is already enabled\n", deviceName)
				return nil
			}
			deviceConfig.Devices[i].Enabled = true
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("Device '%s' not found in configuration\n", deviceName)
		fmt.Printf("\nAvailable devices:\n")
		for _, device := range deviceConfig.Devices {
			status := "disabled"
			if device.Enabled {
				status = "enabled"
			}
			fmt.Printf("  • %s (%s)\n", device.Name, status)
		}
		return errors.NewValidationError("Device not found", map[string]string{"device": deviceName})
	}

	// Save the updated configuration
	if err := config.SaveDeviceConfig(deviceConfigPath, deviceConfig); err != nil {
		fmt.Printf("Failed to save configuration: %v\n", err)
		return errors.NewInternalError("Failed to save device configuration", err)
	}

	fmt.Printf("✓ Device '%s' has been enabled\n", deviceName)
	fmt.Printf("✓ Configuration saved to: %s\n", deviceConfigPath)
	fmt.Printf("\nYou can now start the gateway to begin monitoring this device.\n")
	
	return nil
}

// handleListDevices handles the list-devices command
func (c *CLI) handleListDevices(ctx *Context) error {
	deviceConfigPath := ctx.Flags["devices"].(string)

	// Load device config
	deviceConfig, err := config.LoadDeviceConfig(deviceConfigPath)
	if err != nil {
		fmt.Printf("Failed to load device configuration: %v\n", err)
		return errors.NewConfigError("Failed to load device configuration", err)
	}

	if len(deviceConfig.Devices) == 0 {
		fmt.Printf("No devices found in configuration file: %s\n", deviceConfigPath)
		fmt.Printf("\nUse the 'discover' or 'generate-config' commands to find and configure devices.\n")
		return nil
	}

	fmt.Printf("Device Configuration Summary (%s)\n", deviceConfigPath)
	fmt.Printf("================================%s\n", strings.Repeat("=", len(deviceConfigPath)))
	fmt.Printf("Total devices: %d\n", len(deviceConfig.Devices))
	fmt.Printf("Enabled devices: %d\n", deviceConfig.CountEnabledDevices())
	fmt.Printf("\n")

	for i, device := range deviceConfig.Devices {
		status := "🔴 DISABLED"
		if device.Enabled {
			status = "🟢 ENABLED"
		}
		
		fmt.Printf("%d. %s %s\n", i+1, device.Name, status)
		fmt.Printf("   Address: %s\n", device.Address)
		fmt.Printf("   Topic:   %s\n", device.NATSTopic)
		fmt.Printf("   Events:  %v\n", device.EventTypes)
		if len(device.Metadata) > 0 {
			fmt.Printf("   Metadata: %d items\n", len(device.Metadata))
		}
		fmt.Printf("\n")
	}

	if deviceConfig.CountEnabledDevices() == 0 {
		fmt.Printf("💡 To enable a device, use: %s enable-device -name DEVICE_NAME\n", constants.AppName)
	}

	return nil
}

// handleTestConnection handles the test-connection command
func (c *CLI) handleTestConnection(ctx *Context) error {
	address := ctx.Flags["address"].(string)
	username := ctx.Flags["username"].(string)
	password := ctx.Flags["password"].(string)
	verbose := ctx.Flags["verbose"].(bool)

	if verbose {
		// Set logger to debug level for verbose output
		logger.Initialize(logger.Config{
			Level:  "debug",
			Format: "text",
		})
	}

	fmt.Printf("Testing connectivity to ONVIF device...\n")
	fmt.Printf("Address:  %s\n", address)
	fmt.Printf("Username: %s\n", username)
	fmt.Printf("Password: %s\n", "[hidden]")
	fmt.Printf("\n")

	// Test basic HTTP connectivity
	fmt.Printf("1. Testing basic HTTP connectivity...\n")
	if err := c.testBasicHTTP(address, username, password); err != nil {
		fmt.Printf("❌ HTTP connectivity test failed: %v\n", err)
		return err
	}
	fmt.Printf("✅ HTTP connectivity successful\n\n")

	// Test ONVIF connection
	fmt.Printf("2. Testing ONVIF device creation...\n")
	if err := c.testONVIFConnection(address, username, password, verbose); err != nil {
		fmt.Printf("❌ ONVIF connection test failed: %v\n", err)
		return err
	}
	fmt.Printf("✅ ONVIF connection successful\n\n")

	fmt.Printf("🎉 All connectivity tests passed!\n")
	fmt.Printf("This device should work with the ONVIF-NATS Gateway.\n")

	return nil
}

// testBasicHTTP tests basic HTTP connectivity
func (c *CLI) testBasicHTTP(address, username, password string) error {
	// Build full URL if just host:port provided
	testURL := address
	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		testURL = fmt.Sprintf("http://%s", address)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("   Status Code: %d\n", resp.StatusCode)
	fmt.Printf("   Content-Type: %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("   Server: %s\n", resp.Header.Get("Server"))

	return nil
}

// testONVIFConnection tests ONVIF device creation and basic functionality using proper library patterns
func (c *CLI) testONVIFConnection(address, username, password string, verbose bool) error {
	// Normalize address to the format expected by IOTechSystems/onvif library
	deviceAddr := c.normalizeAddressForLibrary(address)
	
	if verbose {
		fmt.Printf("   Original address: %s\n", address)
		fmt.Printf("   Normalized address: %s\n", deviceAddr)
	}

	// Create custom HTTP client with proper timeouts and modern transport
	httpClient := &http.Client{
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

	fmt.Printf("   Creating ONVIF device client...\n")

	// Create device parameters - let the library handle authentication method detection
	deviceParams := onvif.DeviceParams{
		Xaddr:      deviceAddr,
		Username:   username,
		Password:   password,
		HttpClient: httpClient,
		// Don't set AuthMode explicitly - let library auto-detect
	}

	if verbose {
		fmt.Printf("   Device parameters:\n")
		fmt.Printf("     Xaddr: %s\n", deviceParams.Xaddr)
		fmt.Printf("     Username: %s\n", deviceParams.Username)
		fmt.Printf("     Has password: %t\n", len(deviceParams.Password) > 0)
	}

	// Create ONVIF device - this automatically calls GetCapabilities
	onvifDevice, err := onvif.NewDevice(deviceParams)
	if err != nil {
		return fmt.Errorf("failed to create ONVIF device: %w", err)
	}

	fmt.Printf("   ✅ ONVIF device created successfully\n")

	// Test GetDeviceInformation
	fmt.Printf("   Testing GetDeviceInformation...\n")
	getDeviceInfoReq := device.GetDeviceInformation{}
	response, err := onvifDevice.CallMethod(getDeviceInfoReq)
	if err != nil {
		return fmt.Errorf("GetDeviceInformation failed: %w", err)
	}

	fmt.Printf("   ✅ GetDeviceInformation successful\n")
	if verbose {
		fmt.Printf("     Response Status: %d\n", response.StatusCode)
		fmt.Printf("     Content-Type: %s\n", response.Header.Get("Content-Type"))
		fmt.Printf("     Content-Length: %d\n", response.ContentLength)
	}

	// Read and parse device information
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("   ⚠️  Failed to read response body: %v\n", err)
	} else {
		response.Body.Close()
		
		// Try to extract device information
		if manufacturer := c.extractXMLValue(string(bodyBytes), "Manufacturer"); manufacturer != "" {
			fmt.Printf("   📋 Manufacturer: %s\n", manufacturer)
		}
		if model := c.extractXMLValue(string(bodyBytes), "Model"); model != "" {
			fmt.Printf("   📋 Model: %s\n", model)
		}
		if firmware := c.extractXMLValue(string(bodyBytes), "FirmwareVersion"); firmware != "" {
			fmt.Printf("   📋 Firmware: %s\n", firmware)
		}
		if serial := c.extractXMLValue(string(bodyBytes), "SerialNumber"); serial != "" {
			fmt.Printf("   📋 Serial: %s\n", serial)
		}
		
		if verbose {
			fmt.Printf("   Response preview: %s\n", string(bodyBytes[:min(300, len(bodyBytes))]))
		}
	}

	// Test GetCapabilities
	fmt.Printf("   Testing GetCapabilities...\n")
	getCapabilitiesReq := device.GetCapabilities{Category: "All"}
	response, err = onvifDevice.CallMethod(getCapabilitiesReq)
	if err != nil {
		fmt.Printf("   ⚠️  GetCapabilities failed: %v\n", err)
	} else {
		fmt.Printf("   ✅ GetCapabilities successful\n")
		
		// Read capabilities response
		bodyBytes, err := io.ReadAll(response.Body)
		if err == nil {
			response.Body.Close()
			responseStr := string(bodyBytes)
			
			fmt.Printf("   📋 Available services:\n")
			if strings.Contains(responseStr, "Device") {
				fmt.Printf("     • Device Service\n")
			}
			if strings.Contains(responseStr, "Media") {
				fmt.Printf("     • Media Service\n")
			}
			if strings.Contains(responseStr, "Events") {
				fmt.Printf("     • Events Service\n")
			}
			if strings.Contains(responseStr, "PTZ") {
				fmt.Printf("     • PTZ Service\n")
			}
			if strings.Contains(responseStr, "Imaging") {
				fmt.Printf("     • Imaging Service\n")
			}
			if strings.Contains(responseStr, "Analytics") {
				fmt.Printf("     • Analytics Service\n")
			}
			
			if verbose {
				fmt.Printf("   Capabilities response preview: %s\n", responseStr[:min(500, len(responseStr))])
			}
		}
	}

	return nil
}

// extractXMLValue extracts a value from XML using simple string parsing
func (c *CLI) extractXMLValue(xmlStr, tagName string) string {
	// Try with namespace prefix first
	prefixes := []string{"tds:", ""}
	
	for _, prefix := range prefixes {
		startTag := fmt.Sprintf("<%s%s>", prefix, tagName)
		endTag := fmt.Sprintf("</%s%s>", prefix, tagName)
		
		startIdx := strings.Index(xmlStr, startTag)
		if startIdx == -1 {
			continue
		}
		startIdx += len(startTag)
		
		endIdx := strings.Index(xmlStr[startIdx:], endTag)
		if endIdx == -1 {
			continue
		}
		
		value := strings.TrimSpace(xmlStr[startIdx : startIdx+endIdx])
		if value != "" {
			return value
		}
	}
	
	return ""
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
