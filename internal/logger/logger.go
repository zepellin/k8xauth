package logger

import (
	"log/slog"
	"os"
	"strings"
)

var (
	Log *slog.Logger
)

func New(logLevel, logFormat, logFile string) {
	var level slog.Level
	var w *os.File

	// stdout is reserved for the ExecCredential consumed by kubectl.
	if logFile == "" {
		w = os.Stderr
	} else {
		f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			slog.Error("Unable to open log file: " + err.Error())
			os.Exit(1)
		}
		w = f
	}

	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := slog.HandlerOptions{
		Level: slog.Level(level),
	}

	if logFormat == "json" {
		Log = slog.New(slog.NewJSONHandler(w, &opts))
	} else {
		Log = slog.New(slog.NewTextHandler(w, &opts))
	}
}
