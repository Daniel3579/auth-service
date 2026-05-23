package user

import (
	"auth-service/logger"
	"auth-service/utils"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	user_pb "github.com/Daniel3579/user-service-sdk/gen"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
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

func RequestCreate(user_id int) (error, codes.Code) {
	// Подключаемся к gRPC серверу
	var address string = os.Getenv("USER_SERVICE_GRPC_PORT")
	if address == "" {
		logger.Log.Error("USER_SERVICE_GRPC_PORT not set")
		return fmt.Errorf("USER_SERVICE_GRPC_PORT environment variable is not set"), codes.InvalidArgument
	}

	// Загружаем TLS credentials
	tlsCreds, err := loadTLSCredentials()
	if err != nil {
		logger.Log.Error("failed to load TLS credentials", zap.Error(err))
		return fmt.Errorf("Ошибка загрузки TLS credentials: %w", err), codes.Internal
	}

	// Создаем подключение с TLS
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(tlsCreds),
	)
	if err != nil {
		logger.Log.Error("grpc dial auth server failed", zap.Error(err), zap.String("addr", address))
		return fmt.Errorf("Ошибка подключения к gRPC серверу: %w", err), codes.Internal
	}
	defer conn.Close()

	client := user_pb.NewUserServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	accessToken, err := utils.GenerateToken(0, "system", "access", time.Second*10)
	if err != nil {
		logger.Log.Error("refresh token generation failed",
			zap.String("role", "system"),
			zap.Error(err),
		)
		return fmt.Errorf("token generation failed: %v", err), codes.Internal
	}

	md := metadata.Pairs("authorization", accessToken)
	ctx = metadata.NewOutgoingContext(context.Background(), md)

	// Вызов метода Validate без передачи параметров
	resp, err := client.Create(ctx, &user_pb.UserProfile{
		UserId: int32(user_id),
	})
	if err != nil {
		logger.Log.Warn("validate failed", zap.Error(err))
		return err, codes.Unauthenticated
	}

	logger.Log.Debug("Create UserProfile success", zap.Int32("user_id", resp.GetUserId()))
	return nil, codes.OK
}

func RequestDelete(user_id int) (error, codes.Code) {
	// Подключаемся к gRPC серверу
	var address string = os.Getenv("USER_SERVICE_GRPC_PORT")
	if address == "" {
		logger.Log.Error("USER_SERVICE_GRPC_PORT not set")
		return fmt.Errorf("USER_SERVICE_GRPC_PORT environment variable is not set"), codes.InvalidArgument
	}

	// Загружаем TLS credentials
	tlsCreds, err := loadTLSCredentials()
	if err != nil {
		logger.Log.Error("failed to load TLS credentials", zap.Error(err))
		return fmt.Errorf("Ошибка загрузки TLS credentials: %w", err), codes.Internal
	}

	// Создаем подключение с TLS
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(tlsCreds),
	)
	if err != nil {
		logger.Log.Error("grpc dial auth server failed", zap.Error(err), zap.String("addr", address))
		return fmt.Errorf("Ошибка подключения к gRPC серверу: %w", err), codes.Internal
	}
	defer conn.Close()

	client := user_pb.NewUserServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	accessToken, err := utils.GenerateToken(0, "system", "access", time.Second*10)
	if err != nil {
		logger.Log.Error("refresh token generation failed",
			zap.String("role", "system"),
			zap.Error(err),
		)
		return fmt.Errorf("token generation failed: %v", err), codes.Internal
	}

	md := metadata.Pairs("authorization", accessToken)
	ctx = metadata.NewOutgoingContext(context.Background(), md)

	// Вызов метода Validate без передачи параметров
	resp, err := client.Delete(ctx, &user_pb.IdRequest{
		UserId: int32(user_id),
	})
	if err != nil {
		logger.Log.Warn("validate failed", zap.Error(err))
		return err, codes.Unauthenticated
	}

	logger.Log.Debug("Delete UserProfile success", zap.Int32("user_id", resp.GetUserId()))
	return nil, codes.OK
}
