package configs

import (
	"os"

	"gopkg.in/yaml.v2"
)

// Config - минимальная конфигурация сервиса
type Config struct {
	Address  string `yaml:"addr"`
	LogLevel string `yaml:"loglevel"`
}

// Parse возвращает конфигурацию сервиса по yaml файлу
func Parse() (*Config, error) {
	data, err := os.ReadFile("configs.yaml")
	if err != nil {
		return nil, err
	}

	var config Config

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
