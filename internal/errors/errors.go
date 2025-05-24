package errors

import (
	"fmt"
	"net/http"
)

// Error types for consistent error handling across the application
type ErrorType string

const (
	// Configuration errors
	ErrorTypeConfig           ErrorType = "CONFIG_ERROR"
	ErrorTypeConfigValidation ErrorType = "CONFIG_VALIDATION_ERROR"
	
	// Connection errors
	ErrorTypeConnection    ErrorType = "CONNECTION_ERROR"
	ErrorTypeAuthentication ErrorType = "AUTHENTICATION_ERROR"
	ErrorTypeTimeout       ErrorType = "TIMEOUT_ERROR"
	
	// Device errors
	ErrorTypeDeviceNotFound    ErrorType = "DEVICE_NOT_FOUND"
	ErrorTypeDeviceUnavailable ErrorType = "DEVICE_UNAVAILABLE"
	ErrorTypeDeviceAuth        ErrorType = "DEVICE_AUTH_ERROR"
	
	// NATS errors
	ErrorTypeNATSConnection ErrorType = "NATS_CONNECTION_ERROR"
	ErrorTypeNATSPublish    ErrorType = "NATS_PUBLISH_ERROR"
	
	// API errors
	ErrorTypeValidation  ErrorType = "VALIDATION_ERROR"
	ErrorTypeNotFound    ErrorType = "NOT_FOUND"
	ErrorTypeConflict    ErrorType = "CONFLICT"
	ErrorTypeForbidden   ErrorType = "FORBIDDEN"
	ErrorTypeInternal    ErrorType = "INTERNAL_ERROR"
	
	// Discovery errors
	ErrorTypeDiscovery ErrorType = "DISCOVERY_ERROR"
)

// AppError represents a structured application error
type AppError struct {
	Type       ErrorType         `json:"type"`
	Message    string            `json:"message"`
	Details    string            `json:"details,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	Cause      error             `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s - %s", e.Type, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the wrapped error
func (e *AppError) Unwrap() error {
	return e.Cause
}

// HTTPStatus returns the appropriate HTTP status code
func (e *AppError) HTTPStatus() int {
	if e.StatusCode > 0 {
		return e.StatusCode
	}

	switch e.Type {
	case ErrorTypeValidation, ErrorTypeConfigValidation:
		return http.StatusBadRequest
	case ErrorTypeAuthentication, ErrorTypeDeviceAuth:
		return http.StatusUnauthorized
	case ErrorTypeForbidden:
		return http.StatusForbidden
	case ErrorTypeNotFound, ErrorTypeDeviceNotFound:
		return http.StatusNotFound
	case ErrorTypeConflict:
		return http.StatusConflict
	case ErrorTypeTimeout:
		return http.StatusRequestTimeout
	case ErrorTypeConnection, ErrorTypeDeviceUnavailable, ErrorTypeNATSConnection:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// Constructor functions for common errors

// NewConfigError creates a configuration error
func NewConfigError(message string, cause error) *AppError {
	return &AppError{
		Type:    ErrorTypeConfig,
		Message: message,
		Cause:   cause,
	}
}

// NewConfigValidationError creates a configuration validation error
func NewConfigValidationError(message, details string) *AppError {
	return &AppError{
		Type:       ErrorTypeConfigValidation,
		Message:    message,
		Details:    details,
		StatusCode: http.StatusBadRequest,
	}
}

// NewConnectionError creates a connection error
func NewConnectionError(message string, cause error) *AppError {
	return &AppError{
		Type:    ErrorTypeConnection,
		Message: message,
		Cause:   cause,
	}
}

// NewAuthenticationError creates an authentication error
func NewAuthenticationError(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeAuthentication,
		Message:    message,
		StatusCode: http.StatusUnauthorized,
	}
}

// NewDeviceError creates a device-related error
func NewDeviceError(errorType ErrorType, deviceName, message string, cause error) *AppError {
	return &AppError{
		Type:    errorType,
		Message: message,
		Details: fmt.Sprintf("Device: %s", deviceName),
		Cause:   cause,
		Fields:  map[string]string{"device_name": deviceName},
	}
}

// NewNATSError creates a NATS-related error
func NewNATSError(errorType ErrorType, message string, cause error) *AppError {
	return &AppError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// NewValidationError creates a validation error
func NewValidationError(message string, fields map[string]string) *AppError {
	return &AppError{
		Type:       ErrorTypeValidation,
		Message:    message,
		StatusCode: http.StatusBadRequest,
		Fields:     fields,
	}
}

// NewNotFoundError creates a not found error
func NewNotFoundError(resource string) *AppError {
	return &AppError{
		Type:       ErrorTypeNotFound,
		Message:    fmt.Sprintf("%s not found", resource),
		StatusCode: http.StatusNotFound,
	}
}

// NewConflictError creates a conflict error
func NewConflictError(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeConflict,
		Message:    message,
		StatusCode: http.StatusConflict,
	}
}

// NewInternalError creates an internal server error
func NewInternalError(message string, cause error) *AppError {
	return &AppError{
		Type:       ErrorTypeInternal,
		Message:    message,
		Cause:      cause,
		StatusCode: http.StatusInternalServerError,
	}
}

// NewTimeoutError creates a timeout error
func NewTimeoutError(operation string, cause error) *AppError {
	return &AppError{
		Type:    ErrorTypeTimeout,
		Message: fmt.Sprintf("Timeout during %s", operation),
		Cause:   cause,
	}
}

// NewDiscoveryError creates a discovery error
func NewDiscoveryError(message string, cause error) *AppError {
	return &AppError{
		Type:    ErrorTypeDiscovery,
		Message: message,
		Cause:   cause,
	}
}

// Helper functions

// IsType checks if an error is of a specific type
func IsType(err error, errorType ErrorType) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == errorType
	}
	return false
}

// GetType returns the error type if it's an AppError
func GetType(err error) ErrorType {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type
	}
	return ErrorTypeInternal
}

// WithDetails adds details to an existing AppError
func WithDetails(err *AppError, details string) *AppError {
	err.Details = details
	return err
}

// WithFields adds fields to an existing AppError
func WithFields(err *AppError, fields map[string]string) *AppError {
	if err.Fields == nil {
		err.Fields = make(map[string]string)
	}
	for k, v := range fields {
		err.Fields[k] = v
	}
	return err
}

// WithStatusCode sets a custom status code
func WithStatusCode(err *AppError, statusCode int) *AppError {
	err.StatusCode = statusCode
	return err
}

// Wrap wraps a standard error as an AppError
func Wrap(err error, errorType ErrorType, message string) *AppError {
	return &AppError{
		Type:    errorType,
		Message: message,
		Cause:   err,
	}
}
