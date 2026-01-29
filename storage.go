package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
	"strings"
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

// Helper to read generic JSON content
func (s *Storage) readJsonFile(filename string) (interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil, nil // Return null if file doesn't exist
	}
	if err != nil {
		return nil, err
	}

	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Storage) GetTaxRates() (interface{}, error) {
	return s.readJsonFile(TaxRatesFile)
}

func (s *Storage) GetTaxCoreConfig() (interface{}, error) {
	return s.readJsonFile(TaxCoreConfigFile)
}

func (s *Storage) GetVerificationUrl() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile("verification_url.json")
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	// Clean up quotes if they exist (e.g. "http://..." -> http://...)
	cleanUrl := string(data)

	// Try to unmarshal as a JSON string to handle escaped quotes properly
	var jsonStr string
	if err := json.Unmarshal(data, &jsonStr); err == nil {
		cleanUrl = jsonStr
	} else {
		// Fallback: manual trim
		cleanUrl = strings.Trim(cleanUrl, "\" \n\r")
	}

	return cleanUrl, nil
}

// GetRawJSON reads a file and ensures it returns a JSON object/array,
// unwrapping it if it was saved as a JSON string.
func (s *Storage) GetRawJSON(filename string) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(filename)
	if os.IsNotExist(err) || len(data) == 0 {
		return json.RawMessage("null"), nil
	}
	if err != nil {
		return nil, err
	}

	// Check if the file content is actually a JSON string literal (e.g. "{\"foo\":...}")
	// If so, we need to unmarshal the string to get the raw object bytes.
	var strContent string
	if err := json.Unmarshal(data, &strContent); err == nil {
		// It was a string! Return the content of the string as the raw message
		return json.RawMessage(strContent), nil
	}

	// It wasn't a string (it was likely already an object or array), return raw bytes
	return json.RawMessage(data), nil
}
