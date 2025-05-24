package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"onvif-nats-gateway/internal/config"
	"onvif-nats-gateway/internal/constants"
	"onvif-nats-gateway/internal/device"
	"onvif-nats-gateway/internal/logger"
)

// Client wraps the NATS connection and provides publishing capabilities
type Client struct {
	conn      *nats.Conn
	config    *config.NATSConfig
	eventChan <-chan *device.EventData
	logger    *logger.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// PublishStats tracks publishing statistics
type PublishStats struct {
	TotalPublished uint64    `json:"total_published"`
	TotalErrors    uint64    `json:"total_errors"`
	LastPublished  time.Time `json:"last_published"`
	LastError      time.Time `json:"last_error"`
	LastErrorMsg   string    `json:"last_error_message"`
	mu             sync.RWMutex
}

var stats PublishStats

// NewClient creates a new NATS client
func NewClient(cfg *config.NATSConfig, eventChan <-chan *device.EventData) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Client{
		config:    cfg,
		eventChan: eventChan,
		logger:    logger.WithComponent(constants.ComponentNATS),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Connect establishes connection to NATS server
func (c *Client) Connect() error {
	c.logger.WithField("server_url", c.config.URL).Info("Connecting to NATS server")

	// Configure NATS options with safe callback handlers
	opts := []nats.Option{
		nats.Name(constants.AppName),
		nats.Timeout(c.config.ConnectionTimeout),
		nats.ReconnectWait(c.config.ReconnectWait),
		nats.MaxReconnects(c.config.MaxReconnects),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			// Safe callback - check for nil pointers during shutdown
			if c != nil && c.logger != nil && err != nil {
				c.logger.WithField("error", err.Error()).Warn("NATS disconnected")
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			// Safe callback - check for nil pointers during shutdown
			if c != nil && c.logger != nil && nc != nil {
				c.logger.WithField("server_url", nc.ConnectedUrl()).Info("NATS reconnected")
			}
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			// Safe callback - check for nil pointers during shutdown
			if c != nil && c.logger != nil {
				c.logger.Info("NATS connection closed")
			}
		}),
		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
			// Safe callback - check for nil pointers during shutdown
			if c != nil && c.logger != nil && err != nil {
				c.logger.WithField("error", err.Error()).Error("NATS error")
			}
		}),
	}

	// Add authentication if configured
	if c.config.Username != "" && c.config.Password != "" {
		opts = append(opts, nats.UserInfo(c.config.Username, c.config.Password))
	}

	// Connect to NATS
	conn, err := nats.Connect(c.config.URL, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}

	c.conn = conn
	c.logger.WithField("server_url", c.conn.ConnectedUrl()).Info("Connected to NATS server")

	return nil
}

// Start begins processing events and publishing to NATS
func (c *Client) Start() error {
	if c.conn == nil {
		return fmt.Errorf("NATS connection not established")
	}

	c.logger.Info("Starting NATS event publisher")

	// Start event processing goroutines
	workerCount := constants.DefaultNATSWorkerCount
	for i := 0; i < workerCount; i++ {
		c.wg.Add(1)
		go c.eventProcessor(i)
	}

	return nil
}

// Stop gracefully shuts down the NATS client
func (c *Client) Stop() {
	if c.logger != nil {
		c.logger.Info("Stopping NATS client")
	}
	
	// Cancel context to stop workers
	if c.cancel != nil {
		c.cancel()
	}

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Workers finished gracefully
	case <-time.After(5 * time.Second):
		// Timeout waiting for workers
		if c.logger != nil {
			c.logger.Warn("Timeout waiting for NATS workers to finish")
		}
	}

	// Close NATS connection safely
	if c.conn != nil {
		// Flush any pending messages with timeout
		if err := c.conn.FlushTimeout(2 * time.Second); err != nil && c.logger != nil {
			c.logger.WithField("error", err.Error()).Warn("Failed to flush NATS messages during shutdown")
		}
		
		c.conn.Close()
		c.conn = nil
		
		if c.logger != nil {
			c.logger.Info("NATS connection closed")
		}
	}
}

// eventProcessor processes events from the event channel and publishes them
func (c *Client) eventProcessor(workerID int) {
	defer c.wg.Done()

	workerLogger := c.logger.WithField("worker_id", workerID)
	workerLogger.Info("NATS event processor started")

	for {
		select {
		case <-c.ctx.Done():
			workerLogger.Info("NATS event processor stopping")
			return

		case eventData, ok := <-c.eventChan:
			if !ok {
				workerLogger.Info("Event channel closed")
				return
			}

			// Check if we're still connected and context is valid
			if c.ctx.Err() != nil {
				workerLogger.Debug("Context cancelled, skipping event processing")
				return
			}

			if err := c.publishEvent(eventData); err != nil {
				// Only log if we're not shutting down
				if c.ctx.Err() == nil && c.logger != nil {
					workerLogger.WithFields(map[string]interface{}{
						"error":       err.Error(),
						"device_name": eventData.DeviceName,
						"topic":       eventData.Topic,
					}).Error("Failed to publish event")
				}
				c.updateStats(false, err.Error())
			} else {
				if c.ctx.Err() == nil && c.logger != nil {
					workerLogger.WithFields(map[string]interface{}{
						"device_name": eventData.DeviceName,
						"topic":       eventData.Topic,
						"event_type":  eventData.EventType,
					}).Debug("Published event")
				}
				c.updateStats(true, "")
			}
		}
	}
}

// publishEvent publishes a single event to NATS
func (c *Client) publishEvent(eventData *device.EventData) error {
	// Check if connection is still valid
	if c.conn == nil {
		return fmt.Errorf("NATS connection is nil")
	}

	if !c.conn.IsConnected() {
		return fmt.Errorf("NATS connection is not active")
	}

	// Check if context is cancelled (shutting down)
	if c.ctx.Err() != nil {
		return fmt.Errorf("client is shutting down")
	}

	// Convert event data to JSON
	payload, err := json.Marshal(eventData)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %w", err)
	}

	// Publish to NATS topic
	if err := c.conn.Publish(eventData.Topic, payload); err != nil {
		return fmt.Errorf("failed to publish to topic %s: %w", eventData.Topic, err)
	}

	return nil
}

// PublishEventDirect publishes an event directly (useful for testing)
func (c *Client) PublishEventDirect(topic string, data interface{}) error {
	if c.conn == nil {
		return fmt.Errorf("NATS connection not established")
	}

	if !c.conn.IsConnected() {
		return fmt.Errorf("NATS connection is not active")
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	return c.conn.Publish(topic, payload)
}

// Request makes a request-response call via NATS
func (c *Client) Request(subject string, data []byte, timeout time.Duration) (*nats.Msg, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("NATS connection not established")
	}

	if !c.conn.IsConnected() {
		return nil, fmt.Errorf("NATS connection is not active")
	}

	return c.conn.Request(subject, data, timeout)
}

// Subscribe subscribes to a NATS subject
func (c *Client) Subscribe(subject string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("NATS connection not established")
	}

	if !c.conn.IsConnected() {
		return nil, fmt.Errorf("NATS connection is not active")
	}

	return c.conn.Subscribe(subject, handler)
}

// QueueSubscribe subscribes to a NATS subject with queue group
func (c *Client) QueueSubscribe(subject, queue string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("NATS connection not established")
	}

	if !c.conn.IsConnected() {
		return nil, fmt.Errorf("NATS connection is not active")
	}

	return c.conn.QueueSubscribe(subject, queue, handler)
}

// IsConnected returns true if connected to NATS server
func (c *Client) IsConnected() bool {
	return c.conn != nil && c.conn.IsConnected()
}

// GetConnectionStatus returns detailed connection status
func (c *Client) GetConnectionStatus() map[string]interface{} {
	if c.conn == nil {
		return map[string]interface{}{
			"connected":         false,
			"status":           "not_initialized",
			"server_url":       "",
			"client_id":        "",
			"last_error":       "",
			"bytes_sent":       0,
			"bytes_received":   0,
			"messages_sent":    0,
			"messages_received": 0,
		}
	}

	status := map[string]interface{}{
		"connected":         c.conn.IsConnected(),
		"status":           c.conn.Status().String(),
		"server_url":       c.conn.ConnectedUrl(),
		"client_id":        c.conn.ConnectedServerId(),
		"bytes_sent":       c.conn.OutBytes,
		"bytes_received":   c.conn.InBytes,
		"messages_sent":    c.conn.OutMsgs,
		"messages_received": c.conn.InMsgs,
	}

	if lastErr := c.conn.LastError(); lastErr != nil {
		status["last_error"] = lastErr.Error()
	} else {
		status["last_error"] = ""
	}

	return status
}

// GetPublishStats returns publishing statistics
func (c *Client) GetPublishStats() PublishStats {
	stats.mu.RLock()
	defer stats.mu.RUnlock()
	
	return PublishStats{
		TotalPublished: stats.TotalPublished,
		TotalErrors:    stats.TotalErrors,
		LastPublished:  stats.LastPublished,
		LastError:      stats.LastError,
		LastErrorMsg:   stats.LastErrorMsg,
	}
}

// updateStats updates publishing statistics safely
func (c *Client) updateStats(success bool, errorMsg string) {
	// Skip stats updates if we're shutting down
	if c.ctx != nil && c.ctx.Err() != nil {
		return
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()

	if success {
		stats.TotalPublished++
		stats.LastPublished = time.Now()
	} else {
		stats.TotalErrors++
		stats.LastError = time.Now()
		stats.LastErrorMsg = errorMsg
	}
}

// Flush waits for all pending messages to be sent
func (c *Client) Flush() error {
	if c.conn == nil {
		return fmt.Errorf("NATS connection not established")
	}

	if !c.conn.IsConnected() {
		return fmt.Errorf("NATS connection is not active")
	}

	return c.conn.Flush()
}

// FlushTimeout waits for all pending messages to be sent with timeout
func (c *Client) FlushTimeout(timeout time.Duration) error {
	if c.conn == nil {
		return fmt.Errorf("NATS connection not established")
	}

	if !c.conn.IsConnected() {
		return fmt.Errorf("NATS connection is not active")
	}

	return c.conn.FlushTimeout(timeout)
}
