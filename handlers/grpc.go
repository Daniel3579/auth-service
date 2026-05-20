package handlers

import (
	"auth-service/db"
	"auth-service/logger"
	"auth-service/utils"
	"context"
	"time"

	auth_pb "github.com/Daniel3579/auth-service-sdk/gen"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Server struct {
	auth_pb.UnimplementedAuthServiceServer
}

func (s *Server) SignUp(ctx context.Context, req *auth_pb.AuthRequest) (*auth_pb.SignUpResponse, error) {
	username := req.GetUsername()

	if username == "" || req.GetPassword() == "" {
		logger.Log.Warn("signup attempt with missing credentials", zap.String("username", username))
		return nil, status.Error(codes.InvalidArgument, "username and password required")
	}

	hash, err := utils.HashPassword(req.GetPassword())
	if err != nil {
		logger.Log.Error("password hashing failed",
			zap.String("username", username),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "password hashing failed: %v", err)
	}

	err = db.InsertIntoAuth(&db.InsertRequest{
		Username: username,
		Hash:     hash,
	})
	if err != nil {
		logger.Log.Error("signup failed",
			zap.String("username", username),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "signup failed: %v", err)
	}

	return &auth_pb.SignUpResponse{
		Username: username,
		Hash:     hash,
	}, nil
}

func (s *Server) Validate(ctx context.Context, _ *emptypb.Empty) (*auth_pb.ValidateResponse, error) {
	token, err := utils.GetTokenMetadata(ctx)
	if err != nil {
		logger.Log.Warn("token validation failed: missing token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}

	username, err := utils.IsValid(token, "access")
	if err != nil {
		logger.Log.Warn("invalid access token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	return &auth_pb.ValidateResponse{
		Username: username,
	}, nil
}

func (s *Server) RefreshToken(ctx context.Context, _ *emptypb.Empty) (*auth_pb.RefreshResponse, error) {
	refreshToken, err := utils.GetTokenMetadata(ctx)
	if err != nil {
		logger.Log.Warn("token refresh failed: missing token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}

	username, err := utils.IsValid(refreshToken, "refresh")
	if err != nil {
		logger.Log.Warn("invalid refresh token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	accessToken, err := utils.GenerateToken(username, "access", time.Minute*15)
	if err != nil {
		logger.Log.Error("access token generation failed",
			zap.String("username", username),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "token generation failed: %v", err)
	}

	logger.Log.Info("access token refreshed", zap.String("username", username))
	return &auth_pb.RefreshResponse{
		AccessToken: accessToken,
	}, nil
}

func (s *Server) Login(ctx context.Context, req *auth_pb.AuthRequest) (*auth_pb.LoginResponse, error) {
	username := req.GetUsername()

	hash, err := db.SelectHash(username)
	if err != nil {
		logger.Log.Warn("login attempt for non-existent user", zap.String("username", username))
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	err = utils.CheckPassword(hash, req.GetPassword())
	if err != nil {
		logger.Log.Warn("invalid password attempt", zap.String("username", username))
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	refreshToken, err := utils.GenerateToken(username, "refresh", time.Hour*24*7)
	if err != nil {
		logger.Log.Error("refresh token generation failed",
			zap.String("username", username),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "token generation failed: %v", err)
	}

	accessToken, err := utils.GenerateToken(username, "access", time.Minute*15)
	if err != nil {
		logger.Log.Error("access token generation failed",
			zap.String("username", username),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "token generation failed: %v", err)
	}

	logger.Log.Info("user logged in successfully", zap.String("username", username))
	return &auth_pb.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Server) Delete(ctx context.Context, req *auth_pb.DeleteRequest) (*emptypb.Empty, error) {
	token, err := utils.GetTokenMetadata(ctx)
	if err != nil {
		logger.Log.Warn("delete attempt: missing token")
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}

	tokenUsername, err := utils.IsValid(token, "access")
	if err != nil {
		logger.Log.Warn("delete attempt: invalid token")
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	requestedUsername := req.GetUsername()

	if tokenUsername != requestedUsername {
		logger.Log.Warn("delete attempt: permission denied",
			zap.String("token_username", tokenUsername),
			zap.String("requested_username", requestedUsername),
		)
		return nil, status.Error(codes.PermissionDenied, "can only delete own account")
	}

	err = db.DeleteFromAuth(requestedUsername)
	if err != nil {
		logger.Log.Error("delete account failed",
			zap.String("username", requestedUsername),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "delete failed: %v", err)
	}

	return nil, nil
}
