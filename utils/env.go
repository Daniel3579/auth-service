package utils

import (
	"fmt"

	"github.com/joho/godotenv"
)

func LoadEnv() error {
	err := godotenv.Load()
	if err != nil {
		return fmt.Errorf("Ошибка загрузки файла .env: %w", err)
	}
	return nil
}
