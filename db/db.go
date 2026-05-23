package db

import (
	"auth-service/logger"
	"database/sql"
	"fmt"
	"os"

	auth_pb "github.com/Daniel3579/auth-service-sdk/gen"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

var db *sql.DB

// ——————————————————————————————————————————————————————————————————————————————

type InsertRequest struct {
	Email string
	Hash  string
}

// ——————————————————————————————————————————————————————————————————————————————

func ConnectDB(env string) error {
	var connStr string = os.Getenv(env)

	if connStr == "" {
		logger.Log.Error("DATABASE_URL environment variable is not set")
		return fmt.Errorf("DATABASE_URL not set")
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		logger.Log.Error("Failed to open database", zap.Error(err))
		return fmt.Errorf("Ошибка при открытии базы данных: %w", err)
	}

	err = db.Ping()
	if err != nil {
		logger.Log.Error("Failed to ping database", zap.Error(err))
		return fmt.Errorf("Не удалось пингануть бд: %w", err)
	}

	logger.Log.Info("Successfully connected to database")
	return nil
}

func CloseDB() error {
	if db != nil {
		return db.Close()
	}
	return nil
}

// ——————————————————————————————————————————————————————————————————————————————

func InsertIntoAuth(req *InsertRequest) (*auth_pb.SignUpResponse, error) {
	var res auth_pb.SignUpResponse

	err := db.QueryRow("INSERT INTO users (email, hash) VALUES ($1, $2) Returning *;", req.Email, req.Hash).Scan(&res.Id, &res.Email, &res.Hash)
	if err != nil {
		logger.Log.Error("Failed to insert into users table",
			zap.String("email", req.Email),
			zap.Error(err),
		)
		return nil, fmt.Errorf("Не удалось записать в бд: %w", err)
	}

	logger.Log.Info("User registered successfully", zap.String("email", req.Email))
	return &res, nil
}

func DeleteFromAuth(id int) error {
	res, err := db.Exec("Delete from users where id=$1;", id)
	if err != nil {
		logger.Log.Error("Failed to delete from users table",
			zap.Int("id", id),
			zap.Error(err),
		)
		return fmt.Errorf("Ошибка при попытке удаления: %w", err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		logger.Log.Error("Failed to get rows affected",
			zap.Int("id", id),
			zap.Error(err),
		)
		return fmt.Errorf("Failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		logger.Log.Warn("No rows affected for delete operation", zap.Int("id", id))
		return fmt.Errorf("User not found")
	}

	logger.Log.Info("User deleted successfully", zap.Int("id", id))
	return nil
}

func SelectHash(email string) (int, string, error) {
	var id int
	var hash string

	err := db.QueryRow("Select id, hash from users where email=$1;", email).Scan(&id, &hash)
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Log.Warn("User not found", zap.String("email", email))
			return -1, "", fmt.Errorf("User not found")
		}
		logger.Log.Error("Failed to query hash",
			zap.String("email", email),
			zap.Error(err),
		)
		return -1, "", fmt.Errorf("Не удалось получить хеш: %w", err)
	}

	return id, hash, nil
}
