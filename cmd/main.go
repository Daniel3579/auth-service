package main

import (
	"auth-service/db"
	"auth-service/handlers"
	"auth-service/logger"
	"auth-service/utils"
	"net"
	"os"
	"os/signal"
	"syscall"

	auth_pb "github.com/Daniel3579/auth-service-sdk/gen"
	"go.uber.org/zap"

	mid "auth-service/middleware"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	// init logger
	if err := logger.Init(true); err != nil {
		panic(err)
	}
	defer logger.Sync()

	// ——————————————————————————————————————————————————————————————————————————

	err := utils.LoadEnv()
	if err != nil {
		logger.Log.Fatal("Failed to load environment variables", zap.Error(err))
	}
	logger.Log.Info("Environment variables loaded successfully")

	// ——————————————————————————————————————————————————————————————————————————

	err = db.ConnectDB("DATABASE_URL")
	if err != nil {
		logger.Log.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer func() {
		if err := db.CloseDB(); err != nil {
			logger.Log.Error("Failed to close database connection", zap.Error(err))
		}
	}()
	logger.Log.Info("Database connection established")

	// ——————————————————————————————————————————————————————————————————————————

	certFile := os.Getenv("AUTH_SERVICE_CERT_FILE")
	if certFile == "" {
		logger.Log.Fatal("AUTH_SERVICE_CERT_FILE environment variable is not set")
	}

	keyFile := os.Getenv("AUTH_SERVICE_KEY_FILE")
	if keyFile == "" {
		logger.Log.Fatal("AUTH_SERVICE_KEY_FILE environment variable is not set")
	}

	// Загружаем TLS credentials
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		logger.Log.Fatal("Failed to load TLS credentials: %v", zap.Error(err))
	}

	// Создаем новый gRPC сервер
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(mid.UnaryMetricsInterceptor()),
	)

	// Регистрация сервиса
	auth_pb.RegisterAuthServiceServer(grpcServer, &handlers.Server{})

	// Создаем сетевой слушатель
	var port string = os.Getenv("AUTH_SERVICE_PORT")
	if port == "" {
		logger.Log.Fatal("AUTH_SERVICE_PORT environment variable is not set")
	}

	lis, err := net.Listen("tcp", port)
	if err != nil {
		logger.Log.Fatal("Failed to listen on port", zap.Error(err))
	}
	logger.Log.Info("Task gRPC server is running", zap.String("port", port))

	// ——————————————————————————————————————————————————————————————————————————

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Log.Info("Shutting down gRPC server")
		grpcServer.GracefulStop()
		logger.Log.Info("gRPC server stopped gracefully")
	}()

	if err := grpcServer.Serve(lis); err != nil {
		logger.Log.Fatal("Failed to serve", zap.Error(err))
	}
}
