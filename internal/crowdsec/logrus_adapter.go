// Copyright (c) 2025 jmrplens
// SPDX-License-Identifier: MIT

package crowdsec

import (
	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
)

// zerologAdapter adapts zerolog.Logger to logrus.FieldLogger interface.
// This is needed because go-cs-bouncer's MetricsProvider requires logrus.
type zerologAdapter struct {
	zl zerolog.Logger
}

// NewLogrusAdapter creates a logrus.FieldLogger that delegates to zerolog.
func NewLogrusAdapter(zl zerolog.Logger) logrus.FieldLogger {
	return &zerologAdapter{zl: zl}
}

func (a *zerologAdapter) WithField(key string, value interface{}) *logrus.Entry {
	// Return a logrus entry that will use our adapter as logger
	return logrus.NewEntry(a.asLogrus()).WithField(key, value)
}

func (a *zerologAdapter) WithFields(fields logrus.Fields) *logrus.Entry {
	return logrus.NewEntry(a.asLogrus()).WithFields(fields)
}

func (a *zerologAdapter) WithError(err error) *logrus.Entry {
	return logrus.NewEntry(a.asLogrus()).WithError(err)
}

func (a *zerologAdapter) Debugf(format string, args ...interface{}) {
	a.zl.Debug().Msgf(format, args...)
}

func (a *zerologAdapter) Infof(format string, args ...interface{}) {
	a.zl.Info().Msgf(format, args...)
}

func (a *zerologAdapter) Warnf(format string, args ...interface{}) {
	a.zl.Warn().Msgf(format, args...)
}

func (a *zerologAdapter) Warningf(format string, args ...interface{}) {
	a.zl.Warn().Msgf(format, args...)
}

func (a *zerologAdapter) Errorf(format string, args ...interface{}) {
	a.zl.Error().Msgf(format, args...)
}

func (a *zerologAdapter) Fatalf(format string, args ...interface{}) {
	a.zl.Fatal().Msgf(format, args...)
}

func (a *zerologAdapter) Panicf(format string, args ...interface{}) {
	a.zl.Panic().Msgf(format, args...)
}

func (a *zerologAdapter) Debug(args ...interface{}) {
	a.zl.Debug().Msgf("%v", args...)
}

func (a *zerologAdapter) Info(args ...interface{}) {
	a.zl.Info().Msgf("%v", args...)
}

func (a *zerologAdapter) Warn(args ...interface{}) {
	a.zl.Warn().Msgf("%v", args...)
}

func (a *zerologAdapter) Warning(args ...interface{}) {
	a.zl.Warn().Msgf("%v", args...)
}

func (a *zerologAdapter) Error(args ...interface{}) {
	a.zl.Error().Msgf("%v", args...)
}

func (a *zerologAdapter) Fatal(args ...interface{}) {
	a.zl.Fatal().Msgf("%v", args...)
}

func (a *zerologAdapter) Panic(args ...interface{}) {
	a.zl.Panic().Msgf("%v", args...)
}

func (a *zerologAdapter) Debugln(args ...interface{}) {
	a.zl.Debug().Msgf("%v", args...)
}

func (a *zerologAdapter) Infoln(args ...interface{}) {
	a.zl.Info().Msgf("%v", args...)
}

func (a *zerologAdapter) Warnln(args ...interface{}) {
	a.zl.Warn().Msgf("%v", args...)
}

func (a *zerologAdapter) Warningln(args ...interface{}) {
	a.zl.Warn().Msgf("%v", args...)
}

func (a *zerologAdapter) Errorln(args ...interface{}) {
	a.zl.Error().Msgf("%v", args...)
}

func (a *zerologAdapter) Fatalln(args ...interface{}) {
	a.zl.Fatal().Msgf("%v", args...)
}

func (a *zerologAdapter) Panicln(args ...interface{}) {
	a.zl.Panic().Msgf("%v", args...)
}

func (a *zerologAdapter) Print(args ...interface{}) {
	a.zl.Info().Msgf("%v", args...)
}

func (a *zerologAdapter) Printf(format string, args ...interface{}) {
	a.zl.Info().Msgf(format, args...)
}

func (a *zerologAdapter) Println(args ...interface{}) {
	a.zl.Info().Msgf("%v", args...)
}

// asLogrus creates a minimal logrus.Logger that writes to zerolog.
// Used internally for WithField/WithFields/WithError which need a *logrus.Logger.
func (a *zerologAdapter) asLogrus() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(zerologWriter{zl: a.zl})
	l.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	return l
}

// zerologWriter routes logrus output to zerolog.
type zerologWriter struct {
	zl zerolog.Logger
}

func (w zerologWriter) Write(p []byte) (n int, err error) {
	w.zl.Info().Msg(string(p))
	return len(p), nil
}
