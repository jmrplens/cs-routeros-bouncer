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

func (a *zerologAdapter) WithField(key string, value any) *logrus.Entry {
	// Return a logrus entry that will use our adapter as logger
	return logrus.NewEntry(a.asLogrus()).WithField(key, value)
}

func (a *zerologAdapter) WithFields(fields logrus.Fields) *logrus.Entry {
	return logrus.NewEntry(a.asLogrus()).WithFields(fields)
}

func (a *zerologAdapter) WithError(err error) *logrus.Entry {
	return logrus.NewEntry(a.asLogrus()).WithError(err)
}

func (a *zerologAdapter) Debugf(format string, args ...any) {
	a.zl.Debug().Msgf(format, args...)
}

func (a *zerologAdapter) Infof(format string, args ...any) {
	a.zl.Info().Msgf(format, args...)
}

func (a *zerologAdapter) Warnf(format string, args ...any) {
	a.zl.Warn().Msgf(format, args...)
}

func (a *zerologAdapter) Warningf(format string, args ...any) {
	a.zl.Warn().Msgf(format, args...)
}

func (a *zerologAdapter) Errorf(format string, args ...any) {
	a.zl.Error().Msgf(format, args...)
}

func (a *zerologAdapter) Fatalf(format string, args ...any) {
	a.zl.Fatal().Msgf(format, args...)
}

func (a *zerologAdapter) Panicf(format string, args ...any) {
	a.zl.Panic().Msgf(format, args...)
}

func (a *zerologAdapter) Debug(args ...any) {
	a.zl.Debug().Msg(fmt.Sprint(args...))
}

func (a *zerologAdapter) Info(args ...any) {
	a.zl.Info().Msg(fmt.Sprint(args...))
}

func (a *zerologAdapter) Warn(args ...any) {
	a.zl.Warn().Msg(fmt.Sprint(args...))
}

func (a *zerologAdapter) Warning(args ...any) {
	a.zl.Warn().Msg(fmt.Sprint(args...))
}

func (a *zerologAdapter) Error(args ...any) {
	a.zl.Error().Msg(fmt.Sprint(args...))
}

func (a *zerologAdapter) Fatal(args ...any) {
	a.zl.Fatal().Msg(fmt.Sprint(args...))
}

func (a *zerologAdapter) Panic(args ...any) {
	a.zl.Panic().Msg(fmt.Sprint(args...))
}

func (a *zerologAdapter) Debugln(args ...any) {
	a.zl.Debug().Msg(logrusLine(args...))
}

func (a *zerologAdapter) Infoln(args ...any) {
	a.zl.Info().Msg(logrusLine(args...))
}

func (a *zerologAdapter) Warnln(args ...any) {
	a.zl.Warn().Msg(logrusLine(args...))
}

func (a *zerologAdapter) Warningln(args ...any) {
	a.zl.Warn().Msg(logrusLine(args...))
}

func (a *zerologAdapter) Errorln(args ...any) {
	a.zl.Error().Msg(logrusLine(args...))
}

func (a *zerologAdapter) Fatalln(args ...any) {
	a.zl.Fatal().Msg(logrusLine(args...))
}

func (a *zerologAdapter) Panicln(args ...any) {
	a.zl.Panic().Msg(logrusLine(args...))
}

func (a *zerologAdapter) Print(args ...any) {
	a.zl.Info().Msg(fmt.Sprint(args...))
}

func (a *zerologAdapter) Printf(format string, args ...any) {
	a.zl.Info().Msgf(format, args...)
}

func (a *zerologAdapter) Println(args ...any) {
	a.zl.Info().Msg(logrusLine(args...))
}

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

type zerologHook struct {
	zl zerolog.Logger
}

func (h zerologHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

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
