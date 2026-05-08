// Copyright (c) 2025 jmrplens
// SPDX-License-Identifier: MIT

package crowdsec

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
)

// zerologAdapter adapts zerolog.Logger to logrus.FieldLogger interface.
// This is needed because go-cs-bouncer's MetricsProvider requires logrus.
type zerologAdapter struct {
	zl         zerolog.Logger
	logrusOnce sync.Once
	logrus     *logrus.Logger
}

// NewLogrusAdapter creates a logrus.FieldLogger that delegates to zerolog.
func NewLogrusAdapter(zl zerolog.Logger) logrus.FieldLogger {
	return &zerologAdapter{zl: zl}
}

// WithField returns a logrus entry that forwards the field to zerolog.
func (a *zerologAdapter) WithField(key string, value any) *logrus.Entry {
	// Return a logrus entry that will use our adapter as logger
	return logrus.NewEntry(a.asLogrus()).WithField(key, value)
}

// WithFields returns a logrus entry that forwards all fields to zerolog.
func (a *zerologAdapter) WithFields(fields logrus.Fields) *logrus.Entry {
	return logrus.NewEntry(a.asLogrus()).WithFields(fields)
}

// WithError returns a logrus entry that forwards the error field to zerolog.
func (a *zerologAdapter) WithError(err error) *logrus.Entry {
	return logrus.NewEntry(a.asLogrus()).WithError(err)
}

// Debugf logs a formatted debug message.
func (a *zerologAdapter) Debugf(format string, args ...any) {
	a.zl.Debug().Msgf(format, args...)
}

// Infof logs a formatted info message.
func (a *zerologAdapter) Infof(format string, args ...any) {
	a.zl.Info().Msgf(format, args...)
}

// Warnf logs a formatted warning message.
func (a *zerologAdapter) Warnf(format string, args ...any) {
	a.zl.Warn().Msgf(format, args...)
}

// Warningf logs a formatted warning message using the logrus alias name.
func (a *zerologAdapter) Warningf(format string, args ...any) {
	a.zl.Warn().Msgf(format, args...)
}

// Errorf logs a formatted error message.
func (a *zerologAdapter) Errorf(format string, args ...any) {
	a.zl.Error().Msgf(format, args...)
}

// Fatalf logs a formatted fatal message.
func (a *zerologAdapter) Fatalf(format string, args ...any) {
	a.zl.Fatal().Msgf(format, args...)
}

// Panicf logs a formatted panic message.
func (a *zerologAdapter) Panicf(format string, args ...any) {
	a.zl.Panic().Msgf(format, args...)
}

// Debug logs arguments with fmt.Sprint at debug level.
func (a *zerologAdapter) Debug(args ...any) {
	a.zl.Debug().Msg(fmt.Sprint(args...))
}

// Info logs arguments with fmt.Sprint at info level.
func (a *zerologAdapter) Info(args ...any) {
	a.zl.Info().Msg(fmt.Sprint(args...))
}

// Warn logs arguments with fmt.Sprint at warning level.
func (a *zerologAdapter) Warn(args ...any) {
	a.zl.Warn().Msg(fmt.Sprint(args...))
}

// Warning logs arguments with fmt.Sprint using the logrus alias name.
func (a *zerologAdapter) Warning(args ...any) {
	a.zl.Warn().Msg(fmt.Sprint(args...))
}

// Error logs arguments with fmt.Sprint at error level.
func (a *zerologAdapter) Error(args ...any) {
	a.zl.Error().Msg(fmt.Sprint(args...))
}

// Fatal logs arguments with fmt.Sprint at fatal level.
func (a *zerologAdapter) Fatal(args ...any) {
	a.zl.Fatal().Msg(fmt.Sprint(args...))
}

// Panic logs arguments with fmt.Sprint at panic level.
func (a *zerologAdapter) Panic(args ...any) {
	a.zl.Panic().Msg(fmt.Sprint(args...))
}

// Debugln logs logrus-style line arguments at debug level.
func (a *zerologAdapter) Debugln(args ...any) {
	a.zl.Debug().Msg(logrusLine(args...))
}

// Infoln logs logrus-style line arguments at info level.
func (a *zerologAdapter) Infoln(args ...any) {
	a.zl.Info().Msg(logrusLine(args...))
}

// Warnln logs logrus-style line arguments at warning level.
func (a *zerologAdapter) Warnln(args ...any) {
	a.zl.Warn().Msg(logrusLine(args...))
}

// Warningln logs logrus-style line arguments using the logrus alias name.
func (a *zerologAdapter) Warningln(args ...any) {
	a.zl.Warn().Msg(logrusLine(args...))
}

// Errorln logs logrus-style line arguments at error level.
func (a *zerologAdapter) Errorln(args ...any) {
	a.zl.Error().Msg(logrusLine(args...))
}

// Fatalln logs logrus-style line arguments at fatal level.
func (a *zerologAdapter) Fatalln(args ...any) {
	a.zl.Fatal().Msg(logrusLine(args...))
}

// Panicln logs logrus-style line arguments at panic level.
func (a *zerologAdapter) Panicln(args ...any) {
	a.zl.Panic().Msg(logrusLine(args...))
}

// Print logs arguments at info level to match logrus.Print.
func (a *zerologAdapter) Print(args ...any) {
	a.zl.Info().Msg(fmt.Sprint(args...))
}

// Printf logs a formatted message at info level to match logrus.Printf.
func (a *zerologAdapter) Printf(format string, args ...any) {
	a.zl.Info().Msgf(format, args...)
}

// Println logs line arguments at info level to match logrus.Println.
func (a *zerologAdapter) Println(args ...any) {
	a.zl.Info().Msg(logrusLine(args...))
}

// logrusLine formats arguments like logrus line methods without the trailing newline.
func logrusLine(args ...any) string {
	return strings.TrimSuffix(fmt.Sprintln(args...), "\n")
}

// asLogrus creates a minimal logrus.Logger that writes to zerolog.
// Used internally for WithField/WithFields/WithError which need a *logrus.Logger.
func (a *zerologAdapter) asLogrus() *logrus.Logger {
	a.logrusOnce.Do(func() {
		l := logrus.New()
		l.SetOutput(io.Discard)
		l.SetLevel(logrus.TraceLevel)
		l.AddHook(zerologHook{zl: a.zl})
		a.logrus = l
	})
	return a.logrus
}

// zerologHook forwards logrus entries created by WithField(s) into zerolog events.
type zerologHook struct {
	zl zerolog.Logger
}

// Levels subscribes the hook to every logrus level.
func (h zerologHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire converts a logrus entry and its fields into a zerolog event.
func (h zerologHook) Fire(entry *logrus.Entry) error {
	event := h.zl.WithLevel(logrusToZerologLevel(entry.Level))
	if event == nil {
		return nil
	}
	for key, value := range entry.Data {
		if key == logrus.ErrorKey {
			if err, ok := value.(error); ok {
				event = event.Err(err)
				continue
			}
		}
		event = event.Interface(key, value)
	}
	event.Msg(entry.Message)
	return nil
}

// logrusToZerologLevel maps logrus levels to the closest zerolog level.
func logrusToZerologLevel(level logrus.Level) zerolog.Level {
	switch level {
	case logrus.PanicLevel:
		return zerolog.PanicLevel
	case logrus.FatalLevel:
		return zerolog.FatalLevel
	case logrus.ErrorLevel:
		return zerolog.ErrorLevel
	case logrus.WarnLevel:
		return zerolog.WarnLevel
	case logrus.InfoLevel:
		return zerolog.InfoLevel
	case logrus.DebugLevel:
		return zerolog.DebugLevel
	case logrus.TraceLevel:
		return zerolog.TraceLevel
	default:
		return zerolog.InfoLevel
	}
}
