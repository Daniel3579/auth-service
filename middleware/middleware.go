package middleware

import (
	"auth-service/logger"
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// UnaryLoggingInterceptor перехватывает все unary RPC запросы и логирует их
func UnaryMetricsInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := "OK"
		if err != nil {
			if st, ok := status.FromError(err); ok {
				code = st.Code().String()
			} else {
				code = "Unknown"
			}
			logger.Log.Warn("rpc error",
				zap.String("method", info.FullMethod),
				zap.String("code", code),
				zap.Error(err),
			)
		} else {
			logger.Log.Info("rpc completed",
				zap.String("method", info.FullMethod),
				zap.Duration("duration", time.Since(start)),
			)
		}

		return resp, err
	}
}
