# ONVIF-NATS Gateway

A high-performance Go application that bridges ONVIF IP cameras with NATS messaging system. The gateway automatically discovers ONVIF devices, subscribes to their events, and publishes them to configurable NATS topics.

## 🚀 **Quick Wins & Best Practices Implemented**

### **Code Quality & Architecture**
- ✅ **Separation of Concerns**: HTTP API extracted to dedicated package (`internal/api/`)
- ✅ **Structured Logging**: JSON/text logging with component tagging and field support (`internal/logger/`)
- ✅ **Configuration Management**: Split into app config and device config for better maintainability
- ✅ **Error Handling**: Consistent error types with HTTP status mapping (`internal/errors/`)
- ✅ **Constants Management**: All magic numbers and strings centralized (`internal/constants/`)
- ✅ **CLI Interface**: Dedicated CLI package with command handling (`internal/cli/`)

### **Operational Excellence**
- ✅ **Device Discovery**: Automated ONVIF discovery with config generation
- ✅ **Environment Variables**: Support for 12-factor app configuration
- ✅ **Health Checks**: Comprehensive health endpoints for load balancers
- ✅ **Graceful Shutdown**: Proper resource cleanup with timeout handling
- ✅ **Multi-Architecture Builds**: ARM64 and AMD64 support
- ✅ **Enhanced Makefile**: 30+ targets for development, testing, and deployment

### **Security & Production Readiness**
- ✅ **Non-Root Docker**: Runs as non-privileged user
- ✅ **Input Validation**: Configuration validation with meaningful error messages
- ✅ **Security Scanning**: Gosec integration for vulnerability detection
- ✅ **Default Disabled**: Discovered devices disabled by default for security

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

- **Configuration Management**: Split into app config (`config.yaml`) and device config (`devices.yaml`)
- **Structured Logging**: JSON/text formatted logs with component tagging and field support
- **HTTP API**: Dedicated API server package with middleware and proper error handling
- **Device Discovery**: Automated ONVIF device discovery with config generation
- **Event Processing**: Multi-worker NATS publishing with buffering and error handling
- **Health Monitoring**: Device connectivity monitoring and comprehensive status reporting

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
./onvif-nats-gateway -discover

# Generate device configuration from discovery
./onvif-nats-gateway -generate-config -default-username admin -default-password your-password
```

4. **Configure the application**:
```bash
# Copy and edit app configuration
cp config.yaml config.yaml.local
# Edit config.yaml.local with your NATS settings

# Edit devices.yaml to enable discovered devices
# (devices are disabled by default for security)
```

5. **Build and run**:
```bash
make build
./build/onvif-nats-gateway -config config.yaml.local -devices devices.yaml
```

### CLI Commands

```bash
# Discovery commands
./onvif-nats-gateway -discover                              # Discover devices
./onvif-nats-gateway -generate-config -default-username admin -default-password pass  # Generate config

# Runtime options
./onvif-nats-gateway -config app.yaml -devices devices.yaml -port 8080 -log-level debug

# Version info
./onvif-nats-gateway -version
```

### Docker Deployment

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

## Configuration

The application uses split YAML configuration:

### Application Configuration (`config.yaml`)
```yaml
# NATS connection settings
nats:
  url: "nats://localhost:4222"
  username: ""
  password: ""
  connection_timeout: 10s

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
    address: "http://192.168.1.100/onvif/device_service"
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
```

### Environment Variables
- `ONVIF_CONFIG_PATH`: Path to app config file
- `ONVIF_DEVICE_CONFIG_PATH`: Path to device config file
- `ONVIF_LOG_LEVEL`: Override log level
- `ONVIF_HTTP_PORT`: Override HTTP port
- `ONVIF_NATS_URL`: Override NATS URL

## HTTP API Endpoints

The gateway provides several HTTP endpoints for monitoring and management:

### Status Endpoint
```bash
GET /status
```
Returns overall application status including device connections, NATS status, and publishing statistics.

### Health Check
```bash
GET /health
```
Simple health check endpoint for load balancers.

### Device Status
```bash
GET /devices
```
Returns the connection status of all configured devices.

### NATS Status
```bash
GET /nats
```
Returns NATS connection status and publishing statistics.

### Test Event
```bash
POST /test?topic=onvif.test
```
Publishes a test event to the specified NATS topic.

## Event Format

Events published to NATS follow this JSON structure:

```json
{
  "device_name": "camera_01",
  "device_address": "http://192.168.1.100/onvif/device_service",
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

## Common ONVIF Event Types

- `tns1:VideoSource/MotionAlarm` - Motion detection events
- `tns1:AudioAnalytics/Audio/DetectedSound` - Audio detection events  
- `tns1:Device/Trigger/DigitalInput` - Digital input trigger events
- `tns1:VideoAnalytics/ObjectDetection` - Object detection events
- `tns1:Device/HardwareFailure/StorageFailure` - Storage failure events

## Monitoring and Troubleshooting

### Logs
The application provides structured logging. Key log messages include:
- Device discovery results
- Connection status changes
- Event publishing statistics
- Error conditions

### Metrics
Access metrics via the `/status` endpoint:
- Total events published
- Publishing error count
- Device connection status
- NATS connection health

### Common Issues

1. **Device Discovery Fails**
   - Check network connectivity
   - Verify cameras support ONVIF
   - Check firewall settings (UDP port 3702)

2. **Authentication Errors**
   - Verify username/password in config
   - Check camera user permissions
   - Ensure ONVIF services are enabled

3. **Event Subscription Issues**
   - Check camera event configuration
   - Verify event types are supported
   - Monitor subscription renewal logs

4. **NATS Connection Problems**
   - Verify NATS server is running
   - Check connection credentials
   - Monitor reconnection attempts

## Development

### Building from Source
```bash
go build -o onvif-nats-gateway cmd/main.go
```

### Running Tests
```bash
go test ./...
```

### Code Structure
```
├── cmd/
│   └── main.go              # Application entry point and CLI handling
├── internal/
│   ├── api/
│   │   └── server.go        # HTTP API server and handlers
│   ├── config/
│   │   └── config.go        # Configuration management (split configs)
│   ├── constants/
│   │   └── constants.go     # Application constants and defaults
│   ├── device/
│   │   └── device.go        # ONVIF device management and events
│   ├── discovery/
│   │   └── discovery.go     # ONVIF device discovery and config generation
│   ├── logger/
│   │   └── logger.go        # Structured logging with levels and formats
│   └── nats/
│       └── client.go        # NATS client implementation
├── config.yaml              # Application configuration
├── devices.yaml             # Device configuration
├── Dockerfile               # Multi-stage Docker build
├── docker-compose.yml       # Full stack deployment
├── Makefile                 # Build automation and development tools
└── README.md
```

### Adding New Features

1. **New Event Types**: Add event type constants and parsing logic in `device/device.go`
2. **Additional Endpoints**: Add HTTP handlers in `cmd/main.go`
3. **Enhanced Filtering**: Extend the device configuration structure
4. **Metrics**: Add prometheus metrics support in a new `metrics` package

## Performance Considerations

- **Event Buffer**: Configure event channel buffer size based on expected event volume
- **Worker Threads**: Adjust NATS publisher worker count for high-throughput scenarios
- **Connection Pooling**: Consider connection pooling for multiple devices
- **Memory Usage**: Monitor memory usage with large numbers of devices

## Security

- Store sensitive credentials in environment variables or secure key management
- Use TLS for NATS connections in production
- Implement proper network segmentation
- Regular security updates for dependencies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Check the troubleshooting section
- Review application logs
- Create an issue with detailed reproduction steps
