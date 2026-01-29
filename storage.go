package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const (
	ConfigFile         = "config.json"
	TaxRatesFile       = "tax_rates.json"
	TaxCoreConfigFile  = "taxcore_config.json"
	CommandLogFile     = "command_log.json"
)

type Config struct {
	PreferredReader string `json:"preferred_reader"`
	Token           string `json:"token"`
	TokenExpiresAt  string `json:"token_expires_at"`
}

type CommandLogEntry struct {
	ProcessedAt string `json:"processed_at"`
	CommandID   string `json:"command_id"`
	Type        int    `json:"type"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
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

func (s *Storage) SaveTaxRates(data json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.WriteFile(TaxRatesFile, data, 0644)
}

func (s *Storage) SaveTaxCoreConfig(data json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.WriteFile(TaxCoreConfigFile, data, 0644)
}

func (s *Storage) AppendCommandLog(entry CommandLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var logs []CommandLogEntry

	file, err := os.ReadFile(CommandLogFile)
	if err == nil {
		json.Unmarshal(file, &logs)
	}

	entry.ProcessedAt = time.Now().Format(time.RFC3339)
	logs = append(logs, entry)

	data, err := json.MarshalIndent(logs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(CommandLogFile, data, 0644)
}
