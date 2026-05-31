package log

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ctxKey struct{}

func New(prod bool) (*zap.Logger, error) {
	if prod {
		cfg := zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "@timestamp"
		cfg.EncoderConfig.MessageKey = "message"
		cfg.EncoderConfig.LevelKey = "log.level"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		cfg.EncoderConfig.StacktraceKey = "error.stack_trace"
		cfg.Sampling = nil
		return cfg.Build()
	}

	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return cfg.Build()
}

func Into(ctx context.Context, l *zap.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

func From(ctx context.Context) *zap.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*zap.Logger); ok {
		return l
	}
	return zap.L()
}
