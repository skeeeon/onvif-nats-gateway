# ONVIF-NATS Gateway Makefile

# Build variables
BINARY_NAME=onvif-nats-gateway
MAIN_PATH=cmd/main.go
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION=$(shell go version | cut -d' ' -f3)
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.goVersion=${GO_VERSION}"

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Configuration files
APP_CONFIG=config.yaml
DEVICE_CONFIG=devices.yaml
SAMPLE_APP_CONFIG=config.yaml.example
SAMPLE_DEVICE_CONFIG=devices.yaml.example

# Default make target
.DEFAULT_GOAL := build

# Help target
.PHONY: help
help: ## Display this help message
	@echo "ONVIF-NATS Gateway Build System"
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $1, $2}' $(MAKEFILE_LIST)

# Build targets
.PHONY: build
build: ## Build the application
	@echo "Building ${BINARY_NAME} (${VERSION})..."
	@mkdir -p ${BUILD_DIR}
	${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME} ${MAIN_PATH}
	@echo "Built ${BUILD_DIR}/${BINARY_NAME}"

.PHONY: build-linux
build-linux: ## Build for Linux AMD64
	@echo "Building ${BINARY_NAME} for Linux AMD64..."
	@mkdir -p ${BUILD_DIR}
	GOOS=linux GOARCH=amd64 ${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-amd64 ${MAIN_PATH}
	
.PHONY: build-linux-arm64
build-linux-arm64: ## Build for Linux ARM64
	@echo "Building ${BINARY_NAME} for Linux ARM64..."
	@mkdir -p ${BUILD_DIR}
	GOOS=linux GOARCH=arm64 ${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-arm64 ${MAIN_PATH}

.PHONY: build-windows
build-windows: ## Build for Windows AMD64
	@echo "Building ${BINARY_NAME} for Windows AMD64..."
	@mkdir -p ${BUILD_DIR}
	GOOS=windows GOARCH=amd64 ${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-windows-amd64.exe ${MAIN_PATH}

.PHONY: build-darwin
build-darwin: ## Build for macOS AMD64
	@echo "Building ${BINARY_NAME} for macOS AMD64..."
	@mkdir -p ${BUILD_DIR}
	GOOS=darwin GOARCH=amd64 ${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-amd64 ${MAIN_PATH}

.PHONY: build-darwin-arm64
build-darwin-arm64: ## Build for macOS ARM64 (Apple Silicon)
	@echo "Building ${BINARY_NAME} for macOS ARM64..."
	@mkdir -p ${BUILD_DIR}
	GOOS=darwin GOARCH=arm64 ${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-arm64 ${MAIN_PATH}

.PHONY: build-all
build-all: build-linux build-linux-arm64 build-windows build-darwin build-darwin-arm64 ## Build for all platforms

# Development targets
.PHONY: run
run: build config ## Build and run the application
	./${BUILD_DIR}/${BINARY_NAME} -config ${APP_CONFIG} -devices ${DEVICE_CONFIG}

.PHONY: run-dev
run-dev: config ## Run in development mode with live reloading
	@which air > /dev/null || (echo "Installing air..." && go install github.com/cosmtrek/air@latest)
	air

.PHONY: discover
discover: build ## Discover ONVIF devices
	./${BUILD_DIR}/${BINARY_NAME} discover

.PHONY: generate-config
generate-config: build ## Generate device config from discovery (requires -password)
	@if [ -z "$(PASSWORD)" ]; then \
		echo "Usage: make generate-config PASSWORD=your-password [USERNAME=admin]"; \
		exit 1; \
	fi
	./${BUILD_DIR}/${BINARY_NAME} generate-config \
		-username $(or $(USERNAME),admin) \
		-password $(PASSWORD) \
		-output ${DEVICE_CONFIG}

# Configuration targets
.PHONY: config
config: ## Create sample configuration files if they don't exist
	@if [ ! -f ${APP_CONFIG} ]; then \
		echo "Creating sample app configuration: ${APP_CONFIG}"; \
		cp ${APP_CONFIG} ${APP_CONFIG}; \
	fi
	@if [ ! -f ${DEVICE_CONFIG} ]; then \
		echo "Creating empty device configuration: ${DEVICE_CONFIG}"; \
		echo "# Device configuration - use 'make generate-config PASSWORD=xxx' to populate" > ${DEVICE_CONFIG}; \
		echo "devices: []" >> ${DEVICE_CONFIG}; \
	fi

.PHONY: config-samples
config-samples: ## Create sample configuration files
	@echo "Creating sample configurations..."
	cp ${APP_CONFIG} ${SAMPLE_APP_CONFIG} 2>/dev/null || true
	cp ${DEVICE_CONFIG} ${SAMPLE_DEVICE_CONFIG} 2>/dev/null || true

.PHONY: validate-config
validate-config: build ## Validate configuration files
	./${BUILD_DIR}/${BINARY_NAME} validate -config ${APP_CONFIG} -devices ${DEVICE_CONFIG}

# Testing targets
.PHONY: test
test: ## Run tests
	${GOTEST} -v -race ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	${GOTEST} -v -race -coverprofile=coverage.out ./...
	${GOCMD} tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

.PHONY: test-integration
test-integration: ## Run integration tests (requires NATS server)
	@echo "Running integration tests..."
	${GOTEST} -v -tags=integration ./...

.PHONY: benchmark
benchmark: ## Run benchmarks
	${GOTEST} -bench=. -benchmem ./...

# Code quality targets
.PHONY: lint
lint: ## Run linter
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2)
	golangci-lint run --timeout=5m

.PHONY: fmt
fmt: ## Format code
	${GOCMD} fmt ./...
	@which goimports > /dev/null || go install golang.org/x/tools/cmd/goimports@latest
	goimports -w .

.PHONY: vet
vet: ## Run go vet
	${GOCMD} vet ./...

.PHONY: tidy
tidy: ## Tidy go modules
	${GOMOD} tidy
	${GOMOD} verify

.PHONY: security
security: ## Run security analysis
	@which gosec > /dev/null || go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	gosec ./...

.PHONY: verify
verify: fmt vet lint test ## Run all verification steps

# Docker targets
.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t ${BINARY_NAME}:${VERSION} .
	docker tag ${BINARY_NAME}:${VERSION} ${BINARY_NAME}:latest

.PHONY: docker-run
docker-run: docker-build ## Run Docker container
	docker run --rm -p 8080:8080 \
		-v $(pwd)/${APP_CONFIG}:/app/config.yaml \
		-v $(pwd)/${DEVICE_CONFIG}:/app/devices.yaml \
		${BINARY_NAME}:latest

.PHONY: docker-compose-up
docker-compose-up: ## Start with docker-compose
	docker-compose up -d

.PHONY: docker-compose-down
docker-compose-down: ## Stop docker-compose stack
	docker-compose down

.PHONY: docker-compose-logs
docker-compose-logs: ## View docker-compose logs
	docker-compose logs -f

# Installation targets
.PHONY: install
install: build ## Install binary to system
	sudo cp ${BUILD_DIR}/${BINARY_NAME} /usr/local/bin/
	@echo "Installed ${BINARY_NAME} to /usr/local/bin/"

.PHONY: uninstall
uninstall: ## Uninstall binary from system
	sudo rm -f /usr/local/bin/${BINARY_NAME}
	@echo "Uninstalled ${BINARY_NAME}"

# Clean targets
.PHONY: clean
clean: ## Clean build artifacts
	${GOCLEAN}
	rm -rf ${BUILD_DIR}
	rm -f coverage.out coverage.html

.PHONY: clean-all
clean-all: clean ## Clean everything including caches
	${GOMOD} clean -cache
	docker system prune -f

# Release targets
.PHONY: release
release: verify build-all ## Create release packages
	@echo "Creating release ${VERSION}..."
	@mkdir -p ${BUILD_DIR}/release
	@cd ${BUILD_DIR} && \
		tar -czf release/${BINARY_NAME}-${VERSION}-linux-amd64.tar.gz ${BINARY_NAME}-linux-amd64 && \
		tar -czf release/${BINARY_NAME}-${VERSION}-linux-arm64.tar.gz ${BINARY_NAME}-linux-arm64 && \
		tar -czf release/${BINARY_NAME}-${VERSION}-darwin-amd64.tar.gz ${BINARY_NAME}-darwin-amd64 && \
		tar -czf release/${BINARY_NAME}-${VERSION}-darwin-arm64.tar.gz ${BINARY_NAME}-darwin-arm64 && \
		zip release/${BINARY_NAME}-${VERSION}-windows-amd64.zip ${BINARY_NAME}-windows-amd64.exe
	@echo "Release packages created in ${BUILD_DIR}/release/"

.PHONY: changelog
changelog: ## Generate changelog
	@which git-chglog > /dev/null || go install github.com/git-chglog/git-chglog/cmd/git-chglog@latest
	git-chglog -o CHANGELOG.md

# Development utilities
.PHONY: tools
tools: ## Install development tools
	go install github.com/cosmtrek/air@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install github.com/git-chglog/git-chglog/cmd/git-chglog@latest
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2

.PHONY: deps
deps: ## Download dependencies
	${GOMOD} download

.PHONY: deps-update
deps-update: ## Update dependencies
	${GOMOD} get -u ./...
	${GOMOD} tidy

.PHONY: deps-graph
deps-graph: ## Generate dependency graph
	@which godepgraph > /dev/null || go install github.com/kisielk/godepgraph@latest
	godepgraph -s ./... | dot -Tpng -o deps.png
	@echo "Dependency graph: deps.png"

# Monitoring and debugging
.PHONY: profile
profile: build ## Run with CPU profiling
	./${BUILD_DIR}/${BINARY_NAME} -cpuprofile=cpu.prof -config ${APP_CONFIG} -devices ${DEVICE_CONFIG}

.PHONY: trace
trace: build ## Run with execution tracing
	./${BUILD_DIR}/${BINARY_NAME} -trace=trace.out -config ${APP_CONFIG} -devices ${DEVICE_CONFIG}

# Version and info
.PHONY: version
version: ## Show version information
	@echo "Version: ${VERSION}"
	@echo "Build time: ${BUILD_TIME}"
	@echo "Go version: ${GO_VERSION}"

.PHONY: info
info: ## Show build information
	@echo "Binary name: ${BINARY_NAME}"
	@echo "Main path: ${MAIN_PATH}"
	@echo "Build directory: ${BUILD_DIR}"
	@echo "Version: ${VERSION}"
	@echo "Build time: ${BUILD_TIME}"
	@echo "Go version: ${GO_VERSION}"
	@echo "LDFLAGS: ${LDFLAGS}"

# Build targets
.PHONY: build
build: ## Build the application
	@echo "Building ${BINARY_NAME}..."
	@mkdir -p ${BUILD_DIR}
	${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME} ${MAIN_PATH}
	@echo "Built ${BUILD_DIR}/${BINARY_NAME}"

.PHONY: build-linux
build-linux: ## Build for Linux
	@echo "Building ${BINARY_NAME} for Linux..."
	@mkdir -p ${BUILD_DIR}
	GOOS=linux GOARCH=amd64 ${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-amd64 ${MAIN_PATH}
	@echo "Built ${BUILD_DIR}/${BINARY_NAME}-linux-amd64"

.PHONY: build-windows
build-windows: ## Build for Windows
	@echo "Building ${BINARY_NAME} for Windows..."
	@mkdir -p ${BUILD_DIR}
	GOOS=windows GOARCH=amd64 ${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-windows-amd64.exe ${MAIN_PATH}
	@echo "Built ${BUILD_DIR}/${BINARY_NAME}-windows-amd64.exe"

.PHONY: build-darwin
build-darwin: ## Build for macOS
	@echo "Building ${BINARY_NAME} for macOS..."
	@mkdir -p ${BUILD_DIR}
	GOOS=darwin GOARCH=amd64 ${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-amd64 ${MAIN_PATH}
	@echo "Built ${BUILD_DIR}/${BINARY_NAME}-darwin-amd64"

.PHONY: build-all
build-all: build-linux build-windows build-darwin ## Build for all platforms

# Development targets
.PHONY: run
run: ## Run the application
	@if [ ! -f config.yaml ]; then \
		echo "config.yaml not found. Please copy config.yaml.example to config.yaml and configure it."; \
		exit 1; \
	fi
	${GOCMD} run ${MAIN_PATH} -config config.yaml

.PHONY: dev
dev: ## Run in development mode with auto-restart
	@which air > /dev/null || (echo "Installing air..." && go install github.com/cosmtrek/air@latest)
	air

# Testing targets
.PHONY: test
test: ## Run tests
	${GOTEST} -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	${GOTEST} -v -coverprofile=coverage.out ./...
	${GOCMD} tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: test-race
test-race: ## Run tests with race detection
	${GOTEST} -v -race ./...

.PHONY: benchmark
benchmark: ## Run benchmarks
	${GOTEST} -bench=. -benchmem ./...

# Code quality targets
.PHONY: lint
lint: ## Run linter
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.54.2)
	golangci-lint run

.PHONY: fmt
fmt: ## Format code
	${GOCMD} fmt ./...

.PHONY: vet
vet: ## Run go vet
	${GOCMD} vet ./...

.PHONY: tidy
tidy: ## Tidy go modules
	${GOMOD} tidy

.PHONY: verify
verify: fmt vet lint test ## Run all verification steps

# Docker targets
.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t ${BINARY_NAME}:${VERSION} .
	docker tag ${BINARY_NAME}:${VERSION} ${BINARY_NAME}:latest

.PHONY: docker-run
docker-run: ## Run Docker container
	docker run --rm -p 8080:8080 -v $$(pwd)/config.yaml:/app/config.yaml ${BINARY_NAME}:latest

.PHONY: docker-push
docker-push: docker-build ## Push Docker image
	docker push ${BINARY_NAME}:${VERSION}
	docker push ${BINARY_NAME}:latest

# Installation targets
.PHONY: install
install: build ## Install the binary
	sudo cp ${BUILD_DIR}/${BINARY_NAME} /usr/local/bin/
	@echo "Installed ${BINARY_NAME} to /usr/local/bin/"

.PHONY: uninstall
uninstall: ## Uninstall the binary
	sudo rm -f /usr/local/bin/${BINARY_NAME}
	@echo "Uninstalled ${BINARY_NAME}"

# Configuration targets
.PHONY: config
config: ## Create sample configuration file
	@if [ -f config.yaml ]; then \
		echo "config.yaml already exists. Backup created as config.yaml.bak"; \
		cp config.yaml config.yaml.bak; \
	fi
	cp config.yaml config.yaml
	@echo "Sample configuration created: config.yaml"

# Clean targets
.PHONY: clean
clean: ## Clean build artifacts
	${GOCLEAN}
	rm -rf ${BUILD_DIR}
	rm -f coverage.out coverage.html

.PHONY: clean-all
clean-all: clean ## Clean everything including dependencies
	${GOMOD} clean -cache

# Dependency targets
.PHONY: deps
deps: ## Download dependencies
	${GOMOD} download

.PHONY: deps-update
deps-update: ## Update dependencies
	${GOMOD} get -u ./...
	${GOMOD} tidy

# Release targets
.PHONY: release
release: verify build-all ## Create a release
	@echo "Creating release ${VERSION}..."
	@mkdir -p ${BUILD_DIR}/release
	@cd ${BUILD_DIR} && \
		tar -czf release/${BINARY_NAME}-${VERSION}-linux-amd64.tar.gz ${BINARY_NAME}-linux-amd64 && \
		tar -czf release/${BINARY_NAME}-${VERSION}-darwin-amd64.tar.gz ${BINARY_NAME}-darwin-amd64 && \
		zip release/${BINARY_NAME}-${VERSION}-windows-amd64.zip ${BINARY_NAME}-windows-amd64.exe
	@echo "Release packages created in ${BUILD_DIR}/release/"

# Development utilities
.PHONY: gen-mock
gen-mock: ## Generate mocks
	@which mockgen > /dev/null || (echo "Installing mockgen..." && go install github.com/golang/mock/mockgen@latest)
	go generate ./...

.PHONY: tools
tools: ## Install development tools
	go install github.com/cosmtrek/air@latest
	go install github.com/golang/mock/mockgen@latest
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.54.2

# Service management (systemd)
.PHONY: service-install
service-install: install ## Install systemd service
	@echo "Creating systemd service..."
	sudo tee /etc/systemd/system/${BINARY_NAME}.service > /dev/null <<EOF
[Unit]
Description=ONVIF NATS Gateway
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=/opt/${BINARY_NAME}
ExecStart=/usr/local/bin/${BINARY_NAME} -config /opt/${BINARY_NAME}/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
	sudo mkdir -p /opt/${BINARY_NAME}
	sudo cp config.yaml /opt/${BINARY_NAME}/
	sudo systemctl daemon-reload
	@echo "Service installed. Use 'make service-start' to start it."

.PHONY: service-start
service-start: ## Start systemd service
	sudo systemctl start ${BINARY_NAME}
	sudo systemctl enable ${BINARY_NAME}
	@echo "Service started and enabled"

.PHONY: service-stop
service-stop: ## Stop systemd service
	sudo systemctl stop ${BINARY_NAME}
	sudo systemctl disable ${BINARY_NAME}
	@echo "Service stopped and disabled"

.PHONY: service-status
service-status: ## Check service status
	sudo systemctl status ${BINARY_NAME}

.PHONY: service-logs
service-logs: ## View service logs
	sudo journalctl -u ${BINARY_NAME} -f

.PHONY: service-uninstall
service-uninstall: service-stop ## Uninstall systemd service
	sudo rm -f /etc/systemd/system/${BINARY_NAME}.service
	sudo rm -rf /opt/${BINARY_NAME}
	sudo systemctl daemon-reload
	@echo "Service uninstalled"
