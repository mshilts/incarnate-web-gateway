package audit

import (
	"context"
	"log/slog"
)

type Logger struct {
	logger *slog.Logger
}

func New(logger *slog.Logger) Logger {
	return Logger{logger: logger}
}

func (l Logger) Event(ctx context.Context, name string, attrs ...any) {
	if l.logger == nil {
		return
	}
	l.logger.InfoContext(ctx, name, attrs...)
}
