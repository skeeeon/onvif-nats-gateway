# ONVIF-NATS Gateway

A high-performance Go application that bridges ONVIF IP cameras with NATS messaging system. The gateway automatically discovers ONVIF devices, subscribes to their events, and publishes them to configurable NATS topics.

## Overview

The ONVIF-NATS Gateway provides enterprise-grade integration between ONVIF-compatible IP cameras and NATS messaging infrastructure. Built with Go for performance and reliability, it features automatic device discovery, robust event processing, comprehensive CLI tooling, and production-ready monitoring capabilities.

**Key Capabilities:**
- **Automatic Discovery**: WS-Discovery protocol support for zero-configuration device detection
- **Event Processing**: Real-time ONVIF event subscription and NATS publishing with multi-worker architecture
- **Configuration Management**: YAML-based configuration with validation and CLI-assisted setup
- **Production Ready**: Structured logging, health checks, graceful shutdown, and comprehensive error handling
- **CLI Tooling**: Full command-line interface for discovery, configuration, and device management
- **Monitoring**: HTTP API with health endpoints and operational metrics

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  ONVIF Cameras  │───▶│ ONVIF-NATS GW   │───▶│  NATS Server    │
│                 │    │                 │    │                 │
│ • Motion Events │    │ • Discovery     │    │ • Event Topics  │
│ • Audio Events  │    │ • Event Sub     │    │ • Subscribers   │
│ • I/O Events    │    │ • Publishing    │    │ • Distribution  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Component Architecture

- **Device Discovery**: WS-Discovery implementation for automatic ONVIF device detection
- **Event Processing**: PullPoint subscription with multi-worker NATS publishing pipeline
- **Configuration Management**: Split configuration (app settings + device definitions) with validation
- **HTTP API**: RESTful endpoints for monitoring and management
- **CLI Interface**: Comprehensive command-line tools for setup and administration

## Quick Start

### Prerequisites

- Go 1.21 or later
- NATS Server running
- ONVIF-compatible IP cameras on the network

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd onvif-nats-gateway
```

2. Install dependencies:
```bash
go mod download
```

3. **Discover devices and generate configuration**:
```bash
# Discover ONVIF devices on network
./onvif-nats-gateway discover

# Generate device configuration from discovery
./onvif-nats-gateway generate-config -username admin -password your-password
```

4. **Configure the application**:
```bash
# Copy and edit app configuration
cp config.yaml config.yaml.local
# Edit config.yaml.local with your NATS settings

# View and enable discovered devices
./onvif-nats-gateway list-devices
./onvif-nats-gateway enable-device -name "device-name"
```

5. **Build and run**:
```bash
make build
./build/onvif-nats-gateway -config config.yaml.local -devices devices.yaml
```

## CLI Commands

The gateway provides comprehensive command-line tools for device management and configuration.

### Discovery Commands

```bash
# Discover ONVIF devices on network
./onvif-nats-gateway discover

# Discover with verbose output and save report
./onvif-nats-gateway discover -verbose -output discovery-report.yaml

# Generate device configuration from discovery
./onvif-nats-gateway generate-config -username admin -password mypass

# Generate config with custom output file
./onvif-nats-gateway generate-config -username admin -password mypass -output custom-devices.yaml
```

### Configuration Management

```bash
# List all configured devices and their status
./onvif-nats-gateway list-devices

# Enable a specific device for monitoring
./onvif-nats-gateway enable-device -name "camera_name"

# Fix device addresses (normalize URLs)
./onvif-nats-gateway fix-config

# Validate configuration files
./onvif-nats-gateway validate

# Show version information
./onvif-nats-gateway version
```

### Runtime Options

```bash
# Run with custom configuration files
./onvif-nats-gateway -config app.yaml -devices devices.yaml

# Override HTTP port and log level
./onvif-nats-gateway -port 8080 -log-level debug

# Show help
./onvif-nats-gateway -help
```

## Configuration

The application uses dual YAML configuration files for flexibility and maintainability.

### Application Configuration (`config.yaml`)

```yaml
# NATS connection settings
nats:
  url: "nats://localhost:4222"
  username: ""
  password: ""
  connection_timeout: 10s
  reconnect_wait: 2s
  max_reconnects: 5

# ONVIF discovery and event settings
onvif:
  discovery_timeout: 30s
  event_pull_timeout: 60s
  subscription_renew: 300s
  enable_discovery: true
  worker_count: 3
  event_buffer_size: 1000

# HTTP API settings
http:
  port: 8080
  read_timeout: 10s
  write_timeout: 10s

# Logging configuration
logging:
  level: "info"
  format: "json"
  component: "onvif-gateway"
```

### Device Configuration (`devices.yaml`)

```yaml
devices:
  - name: "camera_01"
    address: "http://192.168.1.100:80/onvif/device_service"
    username: "admin"
    password: "password123"
    nats_topic: "onvif.camera_01.events"
    event_types:
      - "tns1:VideoSource/MotionAlarm"
      - "tns1:AudioAnalytics/Audio/DetectedSound"
    metadata:
      location: "front_door"
      building: "main_office"
    enabled: true

  - name: "camera_02"
    address: "http://192.168.1.101:80/onvif/device_service"
    username: "admin"
    password: "password456"
    nats_topic: "onvif.camera_02.events"
    event_types: [] # Empty means all event types
    metadata:
      location: "parking_lot"
      zone: "exterior"
    enabled: false  # Disabled device
```

### Environment Variables

Override configuration settings using environment variables:

- `ONVIF_CONFIG_PATH`: Path to app config file
- `ONVIF_DEVICE_CONFIG_PATH`: Path to device config file
- `ONVIF_LOG_LEVEL`: Override log level
- `ONVIF_HTTP_PORT`: Override HTTP port
- `ONVIF_NATS_URL`: Override NATS URL

## HTTP API Endpoints

The gateway provides HTTP endpoints for monitoring and management:

### Health and Status

```bash
# Simple health check for load balancers
GET /health

# Comprehensive application status
GET /status

# Version information
GET /version
```

### Component Status

```bash
# Device connection status
GET /devices

# NATS connection and publishing statistics
GET /nats
```

### Testing

```bash
# Publish test event to NATS
POST /test?topic=onvif.test
```

### Example Status Response

```json
{
  "status": "running",
  "uptime": "2h15m30s",
  "uptime_ms": 8130000,
  "devices": {
    "camera_01": true,
    "camera_02": false
  },
  "nats": {
    "connected": true,
    "server_url": "nats://localhost:4222"
  },
  "publish_stats": {
    "total_published": 1250,
    "total_errors": 2,
    "last_published": "2024-01-15T10:30:00Z"
  },
  "timestamp": "2024-01-15T10:30:15Z"
}
```

## Event Format

Events published to NATS follow this JSON structure:

```json
{
  "device_name": "camera_01",
  "device_address": "http://192.168.1.100:80/onvif/device_service",
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "tns1:VideoSource/MotionAlarm",
  "topic": "onvif.camera_01.events",
  "data": {
    "Topic": "tns1:VideoSource/MotionAlarm",
    "Source": {
      "SimpleItem": {
        "Name": "VideoSourceConfigurationToken",
        "Value": "VideoSourceConfig"
      }
    },
    "Data": {
      "SimpleItem": {
        "Name": "State",
        "Value": "true"
      }
    }
  },
  "metadata": {
    "location": "front_door",
    "building": "main_office"
  }
}
```

## Supported ONVIF Event Types

- `tns1:VideoSource/MotionAlarm` - Motion detection events
- `tns1:AudioAnalytics/Audio/DetectedSound` - Audio detection events  
- `tns1:Device/Trigger/DigitalInput` - Digital input trigger events
- `tns1:VideoAnalytics/ObjectDetection` - Object detection events
- `tns1:Device/HardwareFailure/StorageFailure` - Storage failure events
- `tns1:VideoSource/GlobalSceneChange/ImagingService` - Tampering events
- `tns1:Recording/Recording/Start` - Recording start events
- `tns1:Recording/Recording/Stop` - Recording stop events

Custom event types starting with `tns1:` are also supported.

## Docker Deployment

### Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o onvif-nats-gateway cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/onvif-nats-gateway .
COPY --from=builder /app/config.yaml .
EXPOSE 8080
CMD ["./onvif-nats-gateway"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  nats:
    image: nats:latest
    ports:
      - "4222:4222"
    
  onvif-gateway:
    build: .
    ports:
      - "8080:8080"
    depends_on:
      - nats
    volumes:
      - ./config.yaml:/root/config.yaml
      - ./devices.yaml:/root/devices.yaml
    environment:
      - ONVIF_NATS_URL=nats://nats:4222
```

## Monitoring and Troubleshooting

### Application Logs

The application provides structured logging with configurable levels and formats:

```bash
# Run with debug logging
./onvif-nats-gateway -log-level debug

# Use text format for development
# Edit config.yaml: logging.format = "text"
```

Key log messages include:
- Device discovery results and connection status
- Event subscription lifecycle and renewal
- NATS connection status and publishing statistics
- Configuration validation and errors

### Common Issues and Solutions

**1. Device Discovery Fails**
```bash
# Check discovery with verbose output
./onvif-nats-gateway discover -verbose

# Troubleshooting steps:
# • Ensure cameras are on the same network
# • Verify ONVIF is enabled on cameras
# • Check firewall settings (UDP port 3702)
# • Try increasing discovery timeout
```

**2. Authentication Errors**
```bash
# Test device connectivity
curl -u username:password 'http://192.168.1.100:80/onvif/device_service'

# Verify credentials in device configuration
./onvif-nats-gateway list-devices
```

**3. No Events Received**
```bash
# Check device status
curl http://localhost:8080/devices

# Verify device is enabled
./onvif-nats-gateway list-devices
./onvif-nats-gateway enable-device -name "device-name"

# Check NATS connectivity
curl http://localhost:8080/nats
```

**4. Configuration Issues**
```bash
# Validate configuration
./onvif-nats-gateway validate

# Fix address format issues
./onvif-nats-gateway fix-config

# Generate fresh configuration
./onvif-nats-gateway generate-config -username admin -password pass
```

### Performance Monitoring

Monitor application performance using the HTTP API:

```bash
# Overall status
curl http://localhost:8080/status

# Publishing statistics
curl http://localhost:8080/nats

# Test event publishing
curl -X POST http://localhost:8080/test?topic=test.events
```

## Development

### Building from Source

```bash
# Build for current platform
go build -o onvif-nats-gateway cmd/main.go

# Build with version information
go build -ldflags="-X main.version=v1.0.0" -o onvif-nats-gateway cmd/main.go

# Cross-platform builds
GOOS=linux GOARCH=amd64 go build -o onvif-nats-gateway-linux-amd64 cmd/main.go
GOOS=windows GOARCH=amd64 go build -o onvif-nats-gateway-windows-amd64.exe cmd/main.go
```

### Running Tests

```bash
go test ./...
go test -v ./internal/...
```

### Code Structure

```
├── cmd/
│   └── main.go              # Application entry point
├── internal/
│   ├── api/
│   │   └── server.go        # HTTP API server and endpoints
│   ├── cli/
│   │   └── cli.go           # Command-line interface
│   ├── config/
│   │   └── config.go        # Configuration management
│   ├── constants/
│   │   └── constants.go     # Application constants
│   ├── device/
│   │   └── device.go        # ONVIF device management
│   ├── discovery/
│   │   └── discovery.go     # Device discovery service
│   ├── errors/
│   │   └── errors.go        # Error handling
│   ├── logger/
│   │   └── logger.go        # Structured logging
│   └── nats/
│       └── client.go        # NATS client implementation
├── config.yaml              # Application configuration
├── devices.yaml             # Device configuration
├── Dockerfile               # Container build
├── docker-compose.yml       # Multi-service deployment
├── Makefile                 # Build automation
└── README.md
```

### Adding New Features

**New CLI Commands**: Add command definitions in `internal/cli/cli.go` with proper flag handling and validation.

**Additional Event Types**: Add event type constants in `internal/constants/constants.go` and update validation in `internal/config/config.go`.

**HTTP Endpoints**: Add new handlers in `internal/api/server.go` with proper middleware and error handling.

**Configuration Options**: Update config structures in `internal/config/config.go` with validation and default values.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with proper tests
4. Ensure all tests pass (`go test ./...`)
5. Update documentation as needed
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Guidelines

- Follow Go best practices and idioms
- Add tests for new functionality
- Update documentation for user-facing changes
- Use structured logging with appropriate levels
- Implement proper error handling with context
- Validate all user inputs and configurations

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Review the troubleshooting section above
- Check application logs with `-log-level debug`
- Test individual components using CLI commands
- Create an issue with detailed reproduction steps and log output
