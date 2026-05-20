package main

import (
	"auth-service/db"
	"auth-service/handlers"
	"auth-service/logger"
	"auth-service/utils"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	auth_pb "github.com/Daniel3579/auth-service-sdk/gen"
	"go.uber.org/zap"

	mid "auth-service/middleware"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	certFile := os.Getenv("AUTH_SERVICE_CERT_FILE")
	keyFile := os.Getenv("AUTH_SERVICE_KEY_FILE")
	caFile := os.Getenv("AUTH_SERVICE_CA_FILE")

	// Загружаем сертификат и ключ клиента (Task сервис)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Загружаем CA сертификат
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   "auth-service", // Имя из CN сертификата Auth
	}

	return credentials.NewTLS(tlsConfig), nil
}

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
	server := &handlers.Server{}
	auth_pb.RegisterAuthServiceServer(grpcServer, server)

	// Создаем сетевой слушатель
	var port string = os.Getenv("AUTH_SERVICE_GRPC_PORT")
	if port == "" {
		logger.Log.Fatal("AUTH_SERVICE_GRPC_PORT environment variable is not set")
	}

	lis, err := net.Listen("tcp", port)
	if err != nil {
		logger.Log.Fatal("Failed to listen on port", zap.Error(err))
	}
	logger.Log.Info("Auth gRPC server is running", zap.String("port", port))

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

	go func() {
		var rest_port string = os.Getenv("AUTH_SERVICE_REST_PORT")
		if rest_port == "" {
			logger.Log.Fatal("AUTH_SERVICE_REST_PORT environment variable is not set")
		}

		// Загружаем TLS credentials
		tlsCreds, err := loadTLSCredentials()
		if err != nil {
			logger.Log.Error("Failed to load TLS credentials", zap.Error(err))
		}

		// Создаем подключение с TLS
		address := "localhost" + port
		conn, err := grpc.NewClient(
			address,
			grpc.WithTransportCredentials(tlsCreds),
		)

		if err != nil {
			logger.Log.Error("gRPC dial auth server failed", zap.Error(err), zap.String("addr", address))
		}
		defer conn.Close()

		client := auth_pb.NewAuthServiceClient(conn)

		hs := &handlers.HttpServer{GrpcSrv: client}
		http.HandleFunc("/signup", handlers.EnableCORS(hs.SignUp))
		http.HandleFunc("/validate", handlers.EnableCORS(hs.Validate))
		http.HandleFunc("/refreshtoken", handlers.EnableCORS(hs.RefreshToken))
		http.HandleFunc("/login", handlers.EnableCORS(hs.Login))
		http.HandleFunc("/delete", handlers.EnableCORS(hs.Delete))

		lis, err := net.Listen("tcp", rest_port)
		if err != nil {
			logger.Log.Fatal("Failed to listen on port", zap.Error(err))
		}
		defer lis.Close()

		logger.Log.Info("Auth REST server is running", zap.String("port", rest_port))
		if err := http.Serve(lis, nil); err != nil {
			logger.Log.Fatal("Failed to serve", zap.Error(err))
		}

	}()

	if err := grpcServer.Serve(lis); err != nil {
		logger.Log.Fatal("Failed to serve", zap.Error(err))
	}
}
