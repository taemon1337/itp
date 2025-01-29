package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// LogLevel represents the logging level
type LogLevel int

const (
	// LevelError only logs errors
	LevelError LogLevel = iota
	// LevelWarn logs warnings and errors
	LevelWarn
	// LevelInfo logs info, warnings and errors
	LevelInfo
	// LevelDebug logs everything including debug messages
	LevelDebug
)

var levelNames = map[LogLevel]string{
	LevelError: "ERROR",
	LevelWarn:  "WARN",
	LevelInfo:  "INFO",
	LevelDebug: "DEBUG",
}

// Logger represents a component logger
type Logger struct {
	component string
	level     LogLevel
	logger    *log.Logger
}

// LogWriter wraps a Logger to implement io.Writer
type LogWriter struct {
	logger *Logger
	level  LogLevel
}

// NewLogWriter creates a new LogWriter that writes to the given logger at the specified level
func NewLogWriter(logger *Logger, level LogLevel) *LogWriter {
	return &LogWriter{
		logger: logger,
		level:  level,
	}
}

// Write implements io.Writer
func (w *LogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		switch w.level {
		case LevelError:
			w.logger.Error("%s", msg)
		case LevelWarn:
			w.logger.Warn("%s", msg)
		case LevelInfo:
			w.logger.Info("%s", msg)
		case LevelDebug:
			w.logger.Debug("%s", msg)
		}
	}
	return len(p), nil
}

// New creates a new logger for a component
func New(component string, level LogLevel) *Logger {
	return &Logger{
		component: component,
		level:     level,
		logger:    log.New(os.Stdout, "", log.LstdFlags),
	}
}

// formatMessage formats a log message with component prefix and level
func (l *Logger) formatMessage(level LogLevel, format string, args ...interface{}) string {
	msg := fmt.Sprintf(format, args...)
	return fmt.Sprintf("[%s][%s] %s", l.component, levelNames[level], msg)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level >= LevelError {
		l.logger.Print(l.formatMessage(LevelError, format, args...))
	}
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level >= LevelWarn {
		l.logger.Print(l.formatMessage(LevelWarn, format, args...))
	}
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level >= LevelInfo {
		l.logger.Print(l.formatMessage(LevelInfo, format, args...))
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level >= LevelDebug {
		l.logger.Print(l.formatMessage(LevelDebug, format, args...))
	}
}

// ParseLevel parses a log level string into a LogLevel
func ParseLevel(level string) (LogLevel, error) {
	switch strings.ToUpper(level) {
	case "ERROR":
		return LevelError, nil
	case "WARN":
		return LevelWarn, nil
	case "INFO":
		return LevelInfo, nil
	case "DEBUG":
		return LevelDebug, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level: %s", level)
	}
}
