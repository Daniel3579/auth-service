package handlers

import (
	"auth-service/db"
	"auth-service/logger"
	user_client "auth-service/user"
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
	email := req.GetEmail()

	if email == "" || req.GetPassword() == "" {
		logger.Log.Warn("signup attempt with missing credentials", zap.String("email", email))
		return nil, status.Error(codes.InvalidArgument, "email and password required")
	}

	hash, err := utils.HashPassword(req.GetPassword())
	if err != nil {
		logger.Log.Error("password hashing failed",
			zap.String("email", email),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "password hashing failed: %v", err)
	}

	res, err := db.InsertIntoAuth(&db.InsertRequest{
		Email: email,
		Hash:  hash,
	})
	if err != nil {
		logger.Log.Error("signup failed",
			zap.String("email", email),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "signup failed: %v", err)
	}

	logger.Log.Info("user sign up successfully", zap.String("email", email))

	user_id := int(res.GetId())
	err, code := user_client.RequestCreate(user_id)
	if err != nil {
		logger.Log.Error("Create UserProfile failed",
			zap.Int("user_id", user_id),
			zap.String("email", email),
			zap.Error(err),
		)

		err = db.DeleteFromAuth(user_id)
		if err != nil {
			logger.Log.Error("delete account failed",
				zap.Int("user_id", user_id),
				zap.String("email", email),
				zap.Error(err),
			)
			return nil, status.Errorf(codes.Internal, "delete failed: %v", err)
		}

		logger.Log.Info("user deleted in successfully",
			zap.Int("user_id", user_id),
			zap.String("email", email),
		)

		return nil, status.Errorf(code, "Create UserProfile failed: %v", err)
	}

	return res, nil
}

func (s *Server) Validate(ctx context.Context, _ *emptypb.Empty) (*auth_pb.ValidateResponse, error) {
	token, err := utils.GetTokenMetadata(ctx)
	if err != nil {
		logger.Log.Warn("token validation failed: missing token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}

	id, role, err := utils.IsValid(token, "access")
	if err != nil {
		logger.Log.Warn("invalid access token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	logger.Log.Info("validate successfully", zap.Int("id", id), zap.String("role", role))
	return &auth_pb.ValidateResponse{
		Id:   int32(id),
		Role: role,
	}, nil
}

func (s *Server) RefreshToken(ctx context.Context, _ *emptypb.Empty) (*auth_pb.RefreshResponse, error) {
	refreshToken, err := utils.GetTokenMetadata(ctx)
	if err != nil {
		logger.Log.Warn("token refresh failed: missing token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}

	id, role, err := utils.IsValid(refreshToken, "refresh")
	if err != nil {
		logger.Log.Warn("invalid refresh token", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	accessToken, err := utils.GenerateToken(id, role, "access", time.Minute*15)
	if err != nil {
		logger.Log.Error("access token generation failed",
			zap.Int("id", id),
			zap.String("role", role),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "token generation failed: %v", err)
	}

	logger.Log.Info("access token refreshed", zap.Int("id", id), zap.String("role", role))
	return &auth_pb.RefreshResponse{
		AccessToken: accessToken,
	}, nil
}

func (s *Server) Login(ctx context.Context, req *auth_pb.AuthRequest) (*auth_pb.LoginResponse, error) {
	email := req.GetEmail()

	id, hash, err := db.SelectHash(email)
	if err != nil {
		logger.Log.Warn("login attempt for non-existent user", zap.String("email", email))
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	err = utils.CheckPassword(hash, req.GetPassword())
	if err != nil {
		logger.Log.Warn("invalid password attempt", zap.String("email", email))
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	refreshToken, err := utils.GenerateToken(id, "user", "refresh", time.Hour*24*7)
	if err != nil {
		logger.Log.Error("refresh token generation failed",
			zap.Int("id", id),
			zap.String("email", email),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "token generation failed: %v", err)
	}

	accessToken, err := utils.GenerateToken(id, "user", "access", time.Minute*15)
	if err != nil {
		logger.Log.Error("access token generation failed",
			zap.Int("id", id),
			zap.String("email", email),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "token generation failed: %v", err)
	}

	logger.Log.Info("user logged in successfully", zap.Int("id", id), zap.String("email", email))
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

	tokenId, tokenRole, err := utils.IsValid(token, "access")
	if err != nil {
		logger.Log.Warn("delete attempt: invalid token")
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	requestedId := int(req.GetId())

	if tokenRole == "user" {
		if tokenId != requestedId {
			logger.Log.Warn("delete attempt: permission denied",
				zap.String("token_role", tokenRole),
				zap.Int("token_id", tokenId),
			)
			return nil, status.Error(codes.PermissionDenied, "can only delete own account")
		}
	}

	err = db.DeleteFromAuth(requestedId)
	if err != nil {
		logger.Log.Error("delete account failed",
			zap.String("token_role", tokenRole),
			zap.Int("token_id", tokenId),
			zap.Error(err),
		)

		return nil, status.Errorf(codes.Internal, "delete failed: %v", err)
	}

	logger.Log.Info("user deleted in successfully", zap.Int("id", requestedId), zap.String("role", tokenRole))

	return nil, nil
}
