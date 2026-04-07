package lib

import (
	"strings"

	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps zap sugared logger.
type Logger struct {
	*zap.SugaredLogger
}

// GinLogger implements io.Writer for Gin.
type GinLogger struct {
	*Logger
}

// FxLogger implements fxevent.Logger.
type FxLogger struct {
	*Logger
}

var (
	globalLogger *Logger
	zapLogger    *zap.Logger
)

// GetLogger returns the process-wide logger.
func GetLogger() Logger {
	if globalLogger == nil {
		logger := newLogger(NewEnv())
		globalLogger = &logger
	}
	return *globalLogger
}

// GetGinLogger returns a writer-friendly logger for Gin.
func (l *Logger) GetGinLogger() GinLogger {
	logger := zapLogger.WithOptions(zap.WithCaller(false))
	return GinLogger{Logger: newSugaredLogger(logger)}
}

// GetFxLogger returns an fx event logger.
func (l *Logger) GetFxLogger() fxevent.Logger {
	logger := zapLogger.WithOptions(zap.WithCaller(false))
	return &FxLogger{Logger: newSugaredLogger(logger)}
}

// LogEvent implements fxevent.Logger.
func (l *FxLogger) LogEvent(event fxevent.Event) {
	switch e := event.(type) {
	case *fxevent.OnStartExecuting:
		l.Debug("OnStart hook executing: ",
			zap.String("callee", e.FunctionName),
			zap.String("caller", e.CallerName),
		)
	case *fxevent.OnStartExecuted:
		if e.Err != nil {
			l.Debug("OnStart hook failed: ",
				zap.String("callee", e.FunctionName),
				zap.String("caller", e.CallerName),
				zap.Error(e.Err),
			)
		} else {
			l.Debug("OnStart hook executed: ",
				zap.String("callee", e.FunctionName),
				zap.String("caller", e.CallerName),
				zap.String("runtime", e.Runtime.String()),
			)
		}
	case *fxevent.OnStopExecuting:
		l.Debug("OnStop hook executing: ",
			zap.String("callee", e.FunctionName),
			zap.String("caller", e.CallerName),
		)
	case *fxevent.OnStopExecuted:
		if e.Err != nil {
			l.Debug("OnStop hook failed: ",
				zap.String("callee", e.FunctionName),
				zap.String("caller", e.CallerName),
				zap.Error(e.Err),
			)
		} else {
			l.Debug("OnStop hook executed: ",
				zap.String("callee", e.FunctionName),
				zap.String("caller", e.CallerName),
				zap.String("runtime", e.Runtime.String()),
			)
		}
	case *fxevent.Supplied:
		l.Debug("supplied: ", zap.String("type", e.TypeName), zap.Error(e.Err))
	case *fxevent.Provided:
		for _, rtype := range e.OutputTypeNames {
			l.Debug("provided: ", e.ConstructorName, " => ", rtype)
		}
	case *fxevent.Decorated:
		for _, rtype := range e.OutputTypeNames {
			l.Debug("decorated: ",
				zap.String("decorator", e.DecoratorName),
				zap.String("type", rtype),
			)
		}
	case *fxevent.Invoking:
		l.Debug("invoking: ", e.FunctionName)
	case *fxevent.Started:
		if e.Err == nil {
			l.Debug("started")
		}
	case *fxevent.LoggerInitialized:
		if e.Err == nil {
			l.Debug("initialized: custom fxevent.Logger -> ", e.ConstructorName)
		}
	}
}

func newSugaredLogger(logger *zap.Logger) *Logger {
	return &Logger{SugaredLogger: logger.Sugar()}
}

func newLogger(env Env) Logger {
	config := zap.NewProductionConfig()
	if env.IsLocal() {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	level := zapcore.InfoLevel
	switch env.LogLevel {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	case "fatal":
		level = zapcore.FatalLevel
	}
	config.Level.SetLevel(level)
	zapLogger, _ = config.Build()
	return *newSugaredLogger(zapLogger)
}

// Write implements io.Writer for Gin's logger middleware.
// Gin writes lines that already end with '\n'; zap adds its own line break, so trim to avoid a blank line after each log.
func (l GinLogger) Write(p []byte) (n int, err error) {
	msg := strings.TrimRight(string(p), "\r\n")
	if msg != "" {
		l.Info(msg)
	}
	return len(p), nil
}

// Printf implements a fmt-like printer for fx.
func (l *FxLogger) Printf(str string, args ...interface{}) {
	if len(args) > 0 {
		l.Debugf(str, args)
	}
	l.Debug(str)
}
