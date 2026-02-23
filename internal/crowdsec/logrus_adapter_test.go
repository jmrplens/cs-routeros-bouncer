// Copyright (c) 2025 jmrplens
// SPDX-License-Identifier: MIT

package crowdsec

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
)

// TestNewLogrusAdapterReturnsFieldLogger verifies that NewLogrusAdapter
// returns a value that satisfies the logrus.FieldLogger interface.
func TestNewLogrusAdapterReturnsFieldLogger(t *testing.T) {
	zl := zerolog.New(zerolog.NewTestWriter(t))
	adapter := NewLogrusAdapter(zl)

	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}

	// Verify it satisfies logrus.FieldLogger at compile time (implicit).
	// Verify it satisfies logrus.FieldLogger (implicit via type of adapter).
}

// TestLogrusAdapterInfof verifies that Infof messages are forwarded to zerolog.
func TestLogrusAdapterInfof(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.InfoLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Infof("hello %s", "world")

	output := buf.String()
	if !strings.Contains(output, "hello world") {
		t.Errorf("expected 'hello world' in output, got: %s", output)
	}
}

// TestLogrusAdapterDebugf verifies that Debugf messages are forwarded.
func TestLogrusAdapterDebugf(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.DebugLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Debugf("debug %d", 42)

	output := buf.String()
	if !strings.Contains(output, "debug 42") {
		t.Errorf("expected 'debug 42' in output, got: %s", output)
	}
}

// TestLogrusAdapterWarnf verifies that Warnf messages are forwarded.
func TestLogrusAdapterWarnf(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.WarnLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Warnf("warning %s", "test")

	output := buf.String()
	if !strings.Contains(output, "warning test") {
		t.Errorf("expected 'warning test' in output, got: %s", output)
	}
}

// TestLogrusAdapterErrorf verifies that Errorf messages are forwarded.
func TestLogrusAdapterErrorf(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.ErrorLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Errorf("error %s", "happened")

	output := buf.String()
	if !strings.Contains(output, "error happened") {
		t.Errorf("expected 'error happened' in output, got: %s", output)
	}
}

// TestLogrusAdapterInfo verifies the non-format Info method.
func TestLogrusAdapterInfo(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.InfoLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Info("info message")

	output := buf.String()
	if !strings.Contains(output, "info message") {
		t.Errorf("expected 'info message' in output, got: %s", output)
	}
}

// TestLogrusAdapterWarningf verifies the Warningf alias for Warnf.
func TestLogrusAdapterWarningf(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.WarnLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Warningf("warning alias %d", 1)

	output := buf.String()
	if !strings.Contains(output, "warning alias 1") {
		t.Errorf("expected 'warning alias 1' in output, got: %s", output)
	}
}

// TestLogrusAdapterPrint verifies that Print delegates to Info level.
func TestLogrusAdapterPrint(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.InfoLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Print("print message")

	output := buf.String()
	if !strings.Contains(output, "print message") {
		t.Errorf("expected 'print message' in output, got: %s", output)
	}
}

// TestLogrusAdapterPrintf verifies that Printf delegates to Info level.
func TestLogrusAdapterPrintf(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.InfoLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Printf("formatted %s %d", "msg", 99)

	output := buf.String()
	if !strings.Contains(output, "formatted msg 99") {
		t.Errorf("expected 'formatted msg 99' in output, got: %s", output)
	}
}

// TestLogrusAdapterDebugFiltered verifies that Debug messages are filtered
// when the zerolog level is set above Debug.
func TestLogrusAdapterDebugFiltered(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.InfoLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Debugf("should not appear")

	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Error("debug message should be filtered at info level")
	}
}

// TestLogrusAdapterWithField verifies that WithField returns a logrus.Entry
// that can be used for logging.
func TestLogrusAdapterWithField(t *testing.T) {
	zl := zerolog.New(zerolog.NewTestWriter(t))
	adapter := NewLogrusAdapter(zl)

	entry := adapter.WithField("key", "value")
	if entry == nil {
		t.Fatal("expected non-nil logrus.Entry from WithField")
	}
}

// TestLogrusAdapterWithFields verifies that WithFields returns a logrus.Entry.
func TestLogrusAdapterWithFields(t *testing.T) {
	zl := zerolog.New(zerolog.NewTestWriter(t))
	adapter := NewLogrusAdapter(zl)

	entry := adapter.WithFields(logrus.Fields{"a": 1, "b": "two"})
	if entry == nil {
		t.Fatal("expected non-nil logrus.Entry from WithFields")
	}
}

// TestLogrusAdapterWithError verifies that WithError returns a logrus.Entry.
func TestLogrusAdapterWithError(t *testing.T) {
	zl := zerolog.New(zerolog.NewTestWriter(t))
	adapter := NewLogrusAdapter(zl)

	entry := adapter.WithError(nil)
	if entry == nil {
		t.Fatal("expected non-nil logrus.Entry from WithError")
	}
}

// TestLogrusAdapterLnVariants verifies that *ln methods produce output.
func TestLogrusAdapterLnVariants(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.DebugLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Debugln("debugln msg")
	if !strings.Contains(buf.String(), "debugln msg") {
		t.Error("Debugln output missing")
	}

	buf.Reset()
	adapter.Infoln("infoln msg")
	if !strings.Contains(buf.String(), "infoln msg") {
		t.Error("Infoln output missing")
	}

	buf.Reset()
	adapter.Warnln("warnln msg")
	if !strings.Contains(buf.String(), "warnln msg") {
		t.Error("Warnln output missing")
	}

	buf.Reset()
	adapter.Warningln("warningln msg")
	if !strings.Contains(buf.String(), "warningln msg") {
		t.Error("Warningln output missing")
	}

	buf.Reset()
	adapter.Errorln("errorln msg")
	if !strings.Contains(buf.String(), "errorln msg") {
		t.Error("Errorln output missing")
	}

	buf.Reset()
	adapter.Println("println msg")
	if !strings.Contains(buf.String(), "println msg") {
		t.Error("Println output missing")
	}
}

// TestZerologWriterWrite verifies the zerologWriter routes bytes to zerolog.
func TestZerologWriterWrite(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.InfoLevel)
	w := zerologWriter{zl: zl}

	n, err := w.Write([]byte("test write"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 10 {
		t.Errorf("expected n=10, got %d", n)
	}
	if !strings.Contains(buf.String(), "test write") {
		t.Errorf("expected 'test write' in output, got: %s", buf.String())
	}
}
