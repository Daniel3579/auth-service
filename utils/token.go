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

func IsValid(token string, tokenType string) (int, string, error) {
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	if len(secretKey) == 0 {
		logger.Log.Error("SECRET_KEY environment variable is not set")
		return -1, "", fmt.Errorf("SECRET_KEY not configured")
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
		return -1, "", fmt.Errorf("invalid token: %w", err)
	}

	// Проверяем тип токена
	claimedType, ok := claims["type"].(string)
	if !ok {
		logger.Log.Warn("token type claim missing or invalid",
			zap.String("expected_type", tokenType),
		)
		return -1, "", fmt.Errorf("token type claim missing")
	}

	if claimedType != tokenType {
		logger.Log.Warn("token type mismatch",
			zap.String("expected_type", tokenType),
			zap.String("actual_type", claimedType),
		)
		return -1, "", fmt.Errorf("invalid token type: expected %s, got %s", tokenType, claimedType)
	}

	// Получаем id из claims
	idd, ok := claims["user_id"].(float64)
	id := int(idd)
	if !ok {
		logger.Log.Warn("id claim missing or invalid")
		return -1, "", fmt.Errorf("id claim missing from token")
	}

	// Получаем role из claims
	role, ok := claims["role"].(string)
	if !ok {
		logger.Log.Warn("id claim missing or invalid")
		return -1, "", fmt.Errorf("id claim missing from token")
	}

	logger.Log.Debug("token validated successfully",
		zap.Int("user_id", id),
		zap.String("role", role),
		zap.String("token_type", tokenType),
	)

	return id, role, nil
}

func GenerateToken(id int, role string, tokenType string, duration time.Duration) (string, error) {
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	if len(secretKey) == 0 {
		logger.Log.Error("SECRET_KEY environment variable is not set")
		return "", fmt.Errorf("SECRET_KEY not configured")
	}

	claims := jwt.MapClaims{
		"user_id": id,
		"role":    role,
		"type":    tokenType,
		"exp":     time.Now().Add(duration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		logger.Log.Error("token signing failed",
			zap.Int("user_id", id),
			zap.String("role", role),
			zap.String("token_type", tokenType),
			zap.Error(err),
		)
		return "", fmt.Errorf("token signing failed: %w", err)
	}

	logger.Log.Debug("token generated successfully",
		zap.Int("user_id", id),
		zap.String("role", role),
		zap.String("token_type", tokenType),
		zap.Duration("duration", duration),
	)

	return signedToken, nil
}
