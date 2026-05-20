package utils

import (
	"auth-service/logger"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

func GetTokenMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Log.Debug("metadata not found in context")
		return "", fmt.Errorf("metadata not found")
	}

	tokens := md["authorization"]
	if len(tokens) == 0 {
		logger.Log.Debug("authorization token not found in metadata")
		return "", fmt.Errorf("authorization token not found")
	}

	return tokens[0], nil
}

func IsValid(token string, tokenType string) (string, error) {
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	if len(secretKey) == 0 {
		logger.Log.Error("SECRET_KEY environment variable is not set")
		return "", fmt.Errorf("SECRET_KEY not configured")
	}

	claims := jwt.MapClaims{}

	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			logger.Log.Warn("unexpected signing method",
				zap.String("algorithm", fmt.Sprintf("%v", token.Header["alg"])),
			)
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		logger.Log.Warn("token parsing failed",
			zap.String("token_type", tokenType),
			zap.Error(err),
		)
		return "", fmt.Errorf("invalid token: %w", err)
	}

	// Проверяем тип токена
	claimedType, ok := claims["type"].(string)
	if !ok {
		logger.Log.Warn("token type claim missing or invalid",
			zap.String("expected_type", tokenType),
		)
		return "", fmt.Errorf("token type claim missing")
	}

	if claimedType != tokenType {
		logger.Log.Warn("token type mismatch",
			zap.String("expected_type", tokenType),
			zap.String("actual_type", claimedType),
		)
		return "", fmt.Errorf("invalid token type: expected %s, got %s", tokenType, claimedType)
	}

	// Получаем username из claims
	username, ok := claims["username"].(string)
	if !ok {
		logger.Log.Warn("username claim missing or invalid")
		return "", fmt.Errorf("username claim missing from token")
	}

	logger.Log.Debug("token validated successfully",
		zap.String("username", username),
		zap.String("token_type", tokenType),
	)

	return username, nil
}

func GenerateToken(username string, tokenType string, duration time.Duration) (string, error) {
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	if len(secretKey) == 0 {
		logger.Log.Error("SECRET_KEY environment variable is not set")
		return "", fmt.Errorf("SECRET_KEY not configured")
	}

	claims := jwt.MapClaims{
		"username": username,
		"type":     tokenType,
		"exp":      time.Now().Add(duration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		logger.Log.Error("token signing failed",
			zap.String("username", username),
			zap.String("token_type", tokenType),
			zap.Error(err),
		)
		return "", fmt.Errorf("token signing failed: %w", err)
	}

	logger.Log.Debug("token generated successfully",
		zap.String("username", username),
		zap.String("token_type", tokenType),
		zap.Duration("duration", duration),
	)

	return signedToken, nil
}
