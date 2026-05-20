package handlers

import (
	"encoding/json"
	"net/http"

	auth_pb "github.com/Daniel3579/auth-service-sdk/gen"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DeleteRequest struct {
	Username string `json:"username"`
}

type HttpServer struct {
	GrpcSrv auth_pb.AuthServiceClient
}

func EnableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func (h *HttpServer) SignUp(w http.ResponseWriter, r *http.Request) {
	var reqBody AuthRequest

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	grpcReq := &auth_pb.AuthRequest{Username: reqBody.Username, Password: reqBody.Password}
	resp, err := h.GrpcSrv.SignUp(r.Context(), grpcReq)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *HttpServer) Validate(w http.ResponseWriter, r *http.Request) {
	accessToken := r.Header.Get("Authorization")
	if accessToken == "" {
		http.Error(w, "Missing Authorization header: ", http.StatusUnauthorized)
		return
	}

	md := metadata.Pairs("authorization", accessToken)
	ctx := metadata.NewOutgoingContext(r.Context(), md)

	resp, err := h.GrpcSrv.Validate(ctx, &emptypb.Empty{})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *HttpServer) RefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Header.Get("Authorization")
	if refreshToken == "" {
		http.Error(w, "Missing Authorization header: ", http.StatusUnauthorized)
		return
	}

	md := metadata.Pairs("authorization", refreshToken)
	ctx := metadata.NewOutgoingContext(r.Context(), md)

	resp, err := h.GrpcSrv.RefreshToken(ctx, &emptypb.Empty{})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *HttpServer) Login(w http.ResponseWriter, r *http.Request) {
	var reqBody AuthRequest

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	grpcReq := &auth_pb.AuthRequest{Username: reqBody.Username, Password: reqBody.Password}
	resp, err := h.GrpcSrv.Login(r.Context(), grpcReq)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *HttpServer) Delete(w http.ResponseWriter, r *http.Request) {
	var reqBody DeleteRequest

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	accessToken := r.Header.Get("Authorization")
	if accessToken == "" {
		http.Error(w, "Missing Authorization header: ", http.StatusUnauthorized)
		return
	}

	md := metadata.Pairs("authorization", accessToken)
	ctx := metadata.NewOutgoingContext(r.Context(), md)

	grpcReq := &auth_pb.DeleteRequest{Username: reqBody.Username}
	resp, err := h.GrpcSrv.Delete(ctx, grpcReq)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
