# Multi-stage build for ONVIF-NATS Gateway

# Stage 1: Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata make

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with version info
ARG VERSION=dev
ARG BUILD_TIME
ARG GO_VERSION
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -extldflags '-static' -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.goVersion=${GO_VERSION}" \
    -a -installsuffix cgo \
    -o onvif-nats-gateway \
    cmd/main.go

# Stage 2: Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata wget

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/onvif-nats-gateway .

# Copy sample configurations
COPY --from=builder /build/config.yaml ./config.yaml.example
COPY --from=builder /build/devices.yaml ./devices.yaml.example

# Create directories for configurations and logs
RUN mkdir -p /app/config /app/logs && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Default command
CMD ["./onvif-nats-gateway", "-config", "config.yaml", "-devices", "devices.yaml"]

# Labels for better metadata
LABEL maintainer="ONVIF-NATS Gateway Team"
LABEL version="${VERSION}"
LABEL description="ONVIF to NATS Gateway - Bridge ONVIF events to NATS messaging"
LABEL org.opencontainers.image.source="https://github.com/yourusername/onvif-nats-gateway"
LABEL org.opencontainers.image.documentation="https://github.com/yourusername/onvif-nats-gateway/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="ONVIF-NATS Gateway"
LABEL org.opencontainers.image.description="Production-ready ONVIF camera event bridge to NATS messaging system"
