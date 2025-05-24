package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

// LogLevel represents the logging level
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogFormat represents the logging format
type LogFormat int

const (
	TEXT LogFormat = iota
	JSON
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Component string                 `json:"component,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
}

// Logger represents the application logger
type Logger struct {
	level     LogLevel
	format    LogFormat
	component string
	fields    map[string]interface{}
}

var (
	globalLogger *Logger
)

// Config represents logger configuration
type Config struct {
	Level     string `yaml:"level"`
	Format    string `yaml:"format"`
	Component string `yaml:"component"`
}

// Initialize initializes the global logger
func Initialize(cfg Config) error {
	level, err := parseLogLevel(cfg.Level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	format, err := parseLogFormat(cfg.Format)
	if err != nil {
		return fmt.Errorf("invalid log format: %w", err)
	}

	globalLogger = &Logger{
		level:     level,
		format:    format,
		component: cfg.Component,
		fields:    make(map[string]interface{}),
	}

	return nil
}

// parseLogLevel parses string log level to LogLevel
func parseLogLevel(level string) (LogLevel, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return DEBUG, nil
	case "INFO":
		return INFO, nil
	case "WARN", "WARNING":
		return WARN, nil
	case "ERROR":
		return ERROR, nil
	case "FATAL":
		return FATAL, nil
	default:
		return INFO, fmt.Errorf("unknown log level: %s", level)
	}
}

// parseLogFormat parses string log format to LogFormat
func parseLogFormat(format string) (LogFormat, error) {
	switch strings.ToLower(format) {
	case "text", "plain":
		return TEXT, nil
	case "json":
		return JSON, nil
	default:
		return JSON, fmt.Errorf("unknown log format: %s", format)
	}
}

// GetLogger returns a logger instance
func GetLogger() *Logger {
	if globalLogger == nil {
		// Initialize with defaults if not configured
		globalLogger = &Logger{
			level:     INFO,
			format:    JSON,
			component: "app",
			fields:    make(map[string]interface{}),
		}
	}
	return globalLogger
}

// WithComponent returns a logger with a specific component
func WithComponent(component string) *Logger {
	logger := GetLogger()
	return &Logger{
		level:     logger.level,
		format:    logger.format,
		component: component,
		fields:    make(map[string]interface{}),
	}
}

// WithFields returns a logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	newFields := make(map[string]interface{})
	
	// Copy existing fields
	for k, v := range l.fields {
		newFields[k] = v
	}
	
	// Add new fields
	for k, v := range fields {
		newFields[k] = v
	}

	return &Logger{
		level:     l.level,
		format:    l.format,
		component: l.component,
		fields:    newFields,
	}
}

// WithField returns a logger with an additional field
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return l.WithFields(map[string]interface{}{key: value})
}

// Debug logs a debug message
func (l *Logger) Debug(message string) {
	l.log(DEBUG, message)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(DEBUG, fmt.Sprintf(format, args...))
}

// Info logs an info message
func (l *Logger) Info(message string) {
	l.log(INFO, message)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(INFO, fmt.Sprintf(format, args...))
}

// Warn logs a warning message
func (l *Logger) Warn(message string) {
	l.log(WARN, message)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(WARN, fmt.Sprintf(format, args...))
}

// Error logs an error message
func (l *Logger) Error(message string) {
	l.log(ERROR, message)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(ERROR, fmt.Sprintf(format, args...))
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(message string) {
	l.log(FATAL, message)
	os.Exit(1)
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(FATAL, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// log performs the actual logging
func (l *Logger) log(level LogLevel, message string) {
	if level < l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level.String(),
		Message:   message,
		Component: l.component,
		Fields:    l.fields,
	}

	// Add caller information for errors and above
	if level >= ERROR {
		if pc, file, line, ok := runtime.Caller(2); ok {
			if fn := runtime.FuncForPC(pc); fn != nil {
				entry.Caller = fmt.Sprintf("%s:%d %s", file, line, fn.Name())
			}
		}
	}

	l.output(entry)
}

// output writes the log entry to stdout
func (l *Logger) output(entry LogEntry) {
	switch l.format {
	case JSON:
		if data, err := json.Marshal(entry); err == nil {
			log.Println(string(data))
		} else {
			log.Printf("Failed to marshal log entry: %v", err)
		}
	case TEXT:
		var fieldsStr string
		if len(entry.Fields) > 0 {
			if data, err := json.Marshal(entry.Fields); err == nil {
				fieldsStr = fmt.Sprintf(" fields=%s", string(data))
			}
		}

		var componentStr string
		if entry.Component != "" {
			componentStr = fmt.Sprintf(" [%s]", entry.Component)
		}

		var callerStr string
		if entry.Caller != "" {
			callerStr = fmt.Sprintf(" caller=%s", entry.Caller)
		}

		log.Printf("%s %s%s %s%s%s",
			entry.Timestamp,
			entry.Level,
			componentStr,
			entry.Message,
			fieldsStr,
			callerStr)
	}
}

// Package-level convenience functions
func Debug(message string) {
	GetLogger().Debug(message)
}

func Debugf(format string, args ...interface{}) {
	GetLogger().Debugf(format, args...)
}

func Info(message string) {
	GetLogger().Info(message)
}

func Infof(format string, args ...interface{}) {
	GetLogger().Infof(format, args...)
}

func Warn(message string) {
	GetLogger().Warn(message)
}

func Warnf(format string, args ...interface{}) {
	GetLogger().Warnf(format, args...)
}

func Error(message string) {
	GetLogger().Error(message)
}

func Errorf(format string, args ...interface{}) {
	GetLogger().Errorf(format, args...)
}

func Fatal(message string) {
	GetLogger().Fatal(message)
}

func Fatalf(format string, args ...interface{}) {
	GetLogger().Fatalf(format, args...)
}
