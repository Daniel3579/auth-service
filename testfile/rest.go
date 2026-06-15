package testfile

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	auth_pb "github.com/Daniel3579/auth-service-sdk/gen"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	contentTypeHeader = "Content-Type"
	applicationJSON   = "application/json"

	authorizationHeader = "Authorization"
	authorizationMeta   = "authorization"
)

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type DeleteRequest struct {
	Id int `json:"id"`
}

type HttpServer struct {
	GrpcSrv auth_pb.AuthServiceClient
}

func EnableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET")
		w.Header().Set("Access-Control-Allow-Headers", contentTypeHeader)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func (h *HttpServer) SignUp(w http.ResponseWriter, r *http.Request) {
	grpcReq, ok := readAuthRequest(w, r)
	if !ok {
		return
	}

	resp, err := h.GrpcSrv.SignUp(r.Context(), grpcReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp)
}

func (h *HttpServer) Validate(w http.ResponseWriter, r *http.Request) {
	ctx, ok := contextWithAuthorization(w, r)
	if !ok {
		return
	}

	resp, err := h.GrpcSrv.Validate(ctx, &emptypb.Empty{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp)
}

func (h *HttpServer) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx, ok := contextWithAuthorization(w, r)
	if !ok {
		return
	}

	resp, err := h.GrpcSrv.RefreshToken(ctx, &emptypb.Empty{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp)
}

func (h *HttpServer) Login(w http.ResponseWriter, r *http.Request) {
	grpcReq, ok := readAuthRequest(w, r)
	if !ok {
		return
	}

	resp, err := h.GrpcSrv.Login(r.Context(), grpcReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp)
}

func (h *HttpServer) Delete(w http.ResponseWriter, r *http.Request) {
	var reqBody DeleteRequest

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ctx, ok := contextWithAuthorization(w, r)
	if !ok {
		return
	}

	grpcReq := &auth_pb.DeleteRequest{Id: int32(reqBody.Id)}
	resp, err := h.GrpcSrv.Delete(ctx, grpcReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp)
}

func readAuthRequest(w http.ResponseWriter, r *http.Request) (*auth_pb.AuthRequest, bool) {
	var reqBody AuthRequest

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return nil, false
	}

	return &auth_pb.AuthRequest{
		Email:    reqBody.Email,
		Password: reqBody.Password,
	}, true
}

func contextWithAuthorization(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	token := strings.TrimSpace(r.Header.Get(authorizationHeader))
	if token == "" {
		http.Error(w, "Missing Authorization header: ", http.StatusUnauthorized)
		return nil, false
	}

	md := metadata.Pairs(authorizationMeta, token)
	return metadata.NewOutgoingContext(r.Context(), md), true
}

func writeJSON(w http.ResponseWriter, response any) {
	w.Header().Set(contentTypeHeader, applicationJSON)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
