package testfile

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Log *zap.Logger

func Init(dev bool) error {
	cfg := newLoggerConfig(dev)

	logger, err := cfg.Build(zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	if err != nil {
		return err
	}

	zap.ReplaceGlobals(logger)
	Log = logger

	return nil
}

func Sync() {
	if Log == nil {
		return
	}

	_ = Log.Sync()
}

func newLoggerConfig(dev bool) zap.Config {
	if dev {
		return zap.NewDevelopmentConfig()
	}

	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	return cfg
}
