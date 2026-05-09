// Copyright (c) 2025 jmrplens
// SPDX-License-Identifier: MIT

package crowdsec

import (
	"bytes"
	"errors"
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

// TestLogrusAdapterInfoMultiArgFormatting verifies logrus-style formatting for
// multi-argument Info calls.
func TestLogrusAdapterInfoMultiArgFormatting(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{name: "single arg", args: []any{"info message"}, expected: "info message"},
		{name: "multiple args", args: []any{"count=", 2}, expected: "count=2"},
		{name: "mixed types", args: []any{"status ", 200, " ok"}, expected: "status 200 ok"},
		{name: "empty and zero", args: []any{"", 0}, expected: "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			zl := zerolog.New(&buf).Level(zerolog.InfoLevel)
			adapter := NewLogrusAdapter(zl)

			adapter.Info(tt.args...)
			if output := buf.String(); !strings.Contains(output, tt.expected) {
				t.Errorf("expected %q in output, got: %s", tt.expected, output)
			}
		})
	}
}

// TestLogrusAdapterPrintlnTrimming verifies that Println output does not keep
// the trailing newline added by fmt.Sprintln.
func TestLogrusAdapterPrintlnTrimming(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantContains    string
		wantNotContains string
	}{
		{name: "single argument", args: []string{"hello"}, wantContains: "hello", wantNotContains: "hello\\n"},
		{name: "multiple arguments", args: []string{"hello", "world"}, wantContains: "hello world", wantNotContains: "hello world\\n"},
		{name: "empty string", args: []string{""}, wantContains: `"level":"info"`, wantNotContains: "\\n"},
		{name: "trailing newline input", args: []string{"hello\n"}, wantContains: "hello", wantNotContains: "hello\\n\\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			zl := zerolog.New(&buf).Level(zerolog.InfoLevel)
			adapter := NewLogrusAdapter(zl)

			stringArgs := make([]any, len(tt.args))
			for i, arg := range tt.args {
				stringArgs[i] = arg
			}

			adapter.Println(stringArgs...)
			output := buf.String()
			if !strings.Contains(output, tt.wantContains) {
				t.Errorf("expected %q in output, got: %s", tt.wantContains, output)
			}
			if strings.Contains(output, tt.wantNotContains) {
				t.Errorf("expected output not to contain %q, got: %s", tt.wantNotContains, output)
			}
		})
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

// TestLogrusAdapterWithFieldDebugPreservesLevel verifies that logrus entries
// created from the adapter keep their log level and fields when forwarded.
func TestLogrusAdapterWithFieldDebugPreservesLevel(t *testing.T) {
	tests := []struct {
		name            string
		level           string
		fields          logrus.Fields
		message         string
		expectedStrings []string
	}{
		{name: "debug single field", level: "debug", fields: logrus.Fields{"key": "value"}, message: "debug with field", expectedStrings: []string{`"level":"debug"`, `"key":"value"`, "debug with field"}},
		{name: "info multiple fields", level: "info", fields: logrus.Fields{"user": "crowdsec", "count": 2}, message: "info with fields", expectedStrings: []string{`"level":"info"`, `"user":"crowdsec"`, `"count":2`, "info with fields"}},
		{name: "warn bool field", level: "warn", fields: logrus.Fields{"enabled": true}, message: "warn with fields", expectedStrings: []string{`"level":"warn"`, `"enabled":true`, "warn with fields"}},
		{name: "error string field", level: "error", fields: logrus.Fields{"component": "stream"}, message: "error with fields", expectedStrings: []string{`"level":"error"`, `"component":"stream"`, "error with fields"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			zl := zerolog.New(&buf).Level(zerolog.DebugLevel)
			adapter := NewLogrusAdapter(zl)
			entry := adapter.WithFields(tt.fields)

			switch tt.level {
			case "debug":
				entry.Debug(tt.message)
			case "info":
				entry.Info(tt.message)
			case "warn":
				entry.Warn(tt.message)
			case "error":
				entry.Error(tt.message)
			default:
				t.Fatalf("unsupported level %q", tt.level)
			}

			output := buf.String()
			for _, expected := range tt.expectedStrings {
				if !strings.Contains(output, expected) {
					t.Errorf("expected %q in output, got: %s", expected, output)
				}
			}
		})
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

// TestLogrusAdapterWithErrorForwardsError verifies logrus error fields become zerolog errors.
func TestLogrusAdapterWithErrorForwardsError(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.DebugLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.WithError(errors.New("router offline")).Error("connect failed")

	output := buf.String()
	for _, expected := range []string{`"level":"error"`, `"error":"router offline"`, "connect failed"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected %q in output, got: %s", expected, output)
		}
	}
}

// TestZerologHookDropsDisabledLevel verifies filtered zerolog levels do not emit entries.
func TestZerologHookDropsDisabledLevel(t *testing.T) {
	var buf bytes.Buffer
	hook := zerologHook{zl: zerolog.New(&buf).Level(zerolog.InfoLevel)}

	if err := hook.Fire(&logrus.Entry{Level: logrus.DebugLevel, Message: "hidden", Data: logrus.Fields{"key": "value"}}); err != nil {
		t.Fatalf("Fire() error: %v", err)
	}
	if got := buf.String(); got != "" {
		t.Fatalf("expected no output for disabled debug level, got %s", got)
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

// TestLogrusAdapterDebug verifies the non-format Debug method.
func TestLogrusAdapterDebug(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.DebugLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Debug("debug plain")

	if !strings.Contains(buf.String(), "debug plain") {
		t.Errorf("expected 'debug plain' in output, got: %s", buf.String())
	}
}

// TestLogrusAdapterWarn verifies the non-format Warn method.
func TestLogrusAdapterWarn(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.WarnLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Warn("warn plain")

	if !strings.Contains(buf.String(), "warn plain") {
		t.Errorf("expected 'warn plain' in output, got: %s", buf.String())
	}
}

// TestLogrusAdapterWarning verifies the non-format Warning alias.
func TestLogrusAdapterWarning(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.WarnLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Warning("warning plain")

	if !strings.Contains(buf.String(), "warning plain") {
		t.Errorf("expected 'warning plain' in output, got: %s", buf.String())
	}
}

// TestLogrusAdapterError verifies the non-format Error method.
func TestLogrusAdapterError(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.ErrorLevel)
	adapter := NewLogrusAdapter(zl)

	adapter.Error("error plain")

	if !strings.Contains(buf.String(), "error plain") {
		t.Errorf("expected 'error plain' in output, got: %s", buf.String())
	}
}

// TestLogrusAdapterPanicf verifies Panicf panics with the message.
func TestLogrusAdapterPanicf(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.PanicLevel)
	adapter := NewLogrusAdapter(zl)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from Panicf")
		}
	}()
	adapter.Panicf("panic %s", "msg")
}

// TestLogrusAdapterPanic verifies Panic panics.
func TestLogrusAdapterPanic(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.PanicLevel)
	adapter := NewLogrusAdapter(zl)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from Panic")
		}
	}()
	adapter.Panic("panic plain")
}

// TestLogrusAdapterPanicln verifies Panicln panics.
func TestLogrusAdapterPanicln(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.PanicLevel)
	adapter := NewLogrusAdapter(zl)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from Panicln")
		}
	}()
	adapter.Panicln("panicln msg")
}

// TestLogrusToZerologLevel verifies every logrus level maps to the expected zerolog level.
func TestLogrusToZerologLevel(t *testing.T) {
	tests := []struct {
		name  string
		level logrus.Level
		want  zerolog.Level
	}{
		{"panic", logrus.PanicLevel, zerolog.PanicLevel},
		{"fatal", logrus.FatalLevel, zerolog.FatalLevel},
		{"error", logrus.ErrorLevel, zerolog.ErrorLevel},
		{"warn", logrus.WarnLevel, zerolog.WarnLevel},
		{"info", logrus.InfoLevel, zerolog.InfoLevel},
		{"debug", logrus.DebugLevel, zerolog.DebugLevel},
		{"trace", logrus.TraceLevel, zerolog.TraceLevel},
		{"default", logrus.Level(99), zerolog.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := logrusToZerologLevel(tt.level); got != tt.want {
				t.Fatalf("logrusToZerologLevel(%v) = %v, want %v", tt.level, got, tt.want)
			}
		})
	}
}

// Note: Fatalf, Fatal, and Fatalln call zerolog.Fatal() which invokes os.Exit(1).
// Testing these would terminate the test process, so they are intentionally excluded.
// Coverage for these 3 trivial one-line pass-throughs is not worth the complexity
// of subprocess testing.
