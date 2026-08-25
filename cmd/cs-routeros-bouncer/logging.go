package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jmrplens/cs-routeros-bouncer/internal/config"
)

// logFileMode is the permission mask used when creating logging.file. Bouncer
// logs record the IP addresses of banned clients, so the file stays readable by
// its owner and the service group only and is never world-readable. The active
// umask can only remove bits from this mask, never add them.
const logFileMode os.FileMode = 0o640

// logOutput owns the file opened for logging.file, if any, so runBouncer can
// release it on the graceful-shutdown path. The zero value is valid and means
// "stderr only".
type logOutput struct {
	file *os.File
}

// Close releases the log file. It is a no-op when logging.file was empty.
func (o logOutput) Close() error {
	if o.file == nil {
		return nil
	}
	return o.file.Close()
}

// configureLogOutput points the global logger at stderr and, when logging.file
// is configured, at that file as well. It returns the handle the caller must
// close during shutdown.
//
// Destination: output goes to BOTH stderr and the file rather than to the file
// alone. The packaged systemd unit leaves stdout/stderr attached to the journal
// and container runtimes collect stderr, so moving output into a file would
// silently break `journalctl -u cs-routeros-bouncer` and `docker logs` for
// every operator who sets the key. The file is an addition, not a redirection.
//
// Parent directories: they are deliberately NOT created. The hardened systemd
// unit grants only ReadWritePaths=/var/log, so a path outside it could not be
// created at runtime anyway, and silently running the equivalent of `mkdir -p`
// on a mistyped path would hide the typo behind a log file nobody ever reads.
// A missing directory is reported as a startup error instead.
func configureLogOutput(logging config.LoggingConfig) (logOutput, error) {
	jsonFormat := logging.Format == "json"

	if logging.File == "" {
		// Default case: stderr only, identical to the behavior that shipped
		// before logging.file was implemented.
		if jsonFormat {
			log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
		}
		return logOutput{}, nil
	}

	// Append rather than truncate so a restart never discards the ban history
	// an operator may still need. The path comes from the operator's own
	// configuration file, not from untrusted input.
	file, err := os.OpenFile(logging.File, os.O_WRONLY|os.O_CREATE|os.O_APPEND, logFileMode)
	if err != nil {
		return logOutput{}, fmt.Errorf("cannot open logging.file %q for appending: %w", logging.File, err)
	}

	writer := zerolog.MultiLevelWriter(
		logWriter(os.Stderr, jsonFormat, false),
		// The file never receives ANSI escapes: they are noise in `less` and
		// break log shippers that parse the text format.
		logWriter(file, jsonFormat, true),
	)
	log.Logger = zerolog.New(writer).With().Timestamp().Logger()
	return logOutput{file: file}, nil
}

// logWriter returns out unchanged for the json format, or wrapped in zerolog's
// human-readable console writer for the text format.
func logWriter(out io.Writer, jsonFormat, noColor bool) io.Writer {
	if jsonFormat {
		return out
	}
	return zerolog.ConsoleWriter{Out: out, NoColor: noColor}
}

// closeLogOutput releases the configured log file. It is called explicitly on
// every exit path out of runBouncer because os.Exit skips deferred calls.
func closeLogOutput(out logOutput) {
	if err := out.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "error closing log file: %v\n", err)
	}
}
