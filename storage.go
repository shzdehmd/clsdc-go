package main

import (
	"encoding/json"
	"os"
	"sync"
)

const ConfigFile = "config.json"

type Config struct {
	PreferredReader string `json:"preferred_reader"`
	Token           string `json:"token"`
	TokenExpiresAt  string `json:"token_expires_at"`
}

type Storage struct {
	mu sync.Mutex
}

func (s *Storage) Load() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var cfg Config
	file, err := os.ReadFile(ConfigFile)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}

	err = json.Unmarshal(file, &cfg)
	return cfg, err
}

func (s *Storage) Save(cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigFile, data, 0644)
}
