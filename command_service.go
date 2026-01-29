package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	CmdSetTaxRates        = 0
	CmdSetTimeServer      = 1
	CmdSetVerificationUrl = 2
	CmdForwardProofAudit  = 5
	CmdSetTaxCoreConfig   = 7
	CmdForwardDirective   = 8
)

type TaxCoreCommand struct {
	CommandId string          `json:"commandId"`
	Type      int             `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	UID       string          `json:"uid"`
}

type CommandService struct {
	storage *Storage
	seSvc   *SecureElementService
	cardSvc *CardService
	timeSvc *TimeService
}

func NewCommandService(storage *Storage, seSvc *SecureElementService, cardSvc *CardService, timeSvc *TimeService) *CommandService {
	return &CommandService{
		storage: storage,
		seSvc:   seSvc,
		cardSvc: cardSvc,
		timeSvc: timeSvc,
	}
}

func (s *CommandService) SyncCommands() ([]CommandLogEntry, error) {
	cfg, err := s.storage.Load()
	if err != nil || cfg.Token == "" {
		return nil, fmt.Errorf("missing authentication token")
	}

	readers := s.cardSvc.GetReaders()
	var activeReader string
	for _, r := range readers {
		if r.IsActive {
			activeReader = r.Name
			break
		}
	}
	if activeReader == "" {
		return nil, fmt.Errorf("no active reader")
	}

	info, err := s.seSvc.GetTaxpayerInfo(activeReader)
	if err != nil {
		return nil, fmt.Errorf("failed to get card info: %w", err)
	}

	commands, err := s.fetchCommands(info.ApiUrl, cfg.Token)
	if err != nil {
		return nil, err
	}

	var results []CommandLogEntry

	for _, cmd := range commands {
		log.Printf("Processing Command ID: %s (Type: %d)", cmd.CommandId, cmd.Type)

		success := true
		var errMsg string

		err := s.processSingleCommand(activeReader, cmd)
		if err != nil {
			success = false
			errMsg = err.Error()
			log.Printf(" > Failed: %v", err)
		} else {
			log.Printf(" > Success")
		}

		if err := s.notifyCommandProcessed(info.ApiUrl, cfg.Token, cmd.CommandId, success); err != nil {
			log.Printf(" > Failed to notify API: %v", err)
		}

		entry := CommandLogEntry{
			ProcessedAt: time.Now().Format(time.RFC3339),
			CommandID:   cmd.CommandId,
			Type:        cmd.Type,
			Success:     success,
			Error:       errMsg,
		}
		s.storage.AppendCommandLog(entry)
		results = append(results, entry)
	}

	return results, nil
}

func (s *CommandService) processSingleCommand(readerName string, cmd TaxCoreCommand) error {
	switch cmd.Type {
	case CmdSetTaxRates:
		return s.storage.SaveTaxRates(cmd.Payload)

	case CmdSetTaxCoreConfig:
		return s.storage.SaveTaxCoreConfig(cmd.Payload)

	case CmdSetVerificationUrl:
		return ioutil.WriteFile("verification_url.json", cmd.Payload, 0644)

	case CmdSetTimeServer:
		err := ioutil.WriteFile("time_server.json", cmd.Payload, 0644)
		if err != nil {
			return err
		}
		go func() {
			if err := s.timeSvc.SyncTime(); err != nil {
				log.Printf("Time Sync Failed: %v", err)
			}
		}()
		return nil

	case CmdForwardProofAudit:
		return s.handleSECommand(readerName, cmd.Payload, s.seSvc.EndAudit)

	case CmdForwardDirective:
		return s.handleSECommand(readerName, cmd.Payload, s.seSvc.ForwardSecureElementDirective)

	default:
		return fmt.Errorf("unknown command type: %d", cmd.Type)
	}
}

func (s *CommandService) handleSECommand(readerName string, rawPayload json.RawMessage, seFunc func(string, []byte) error) error {
	var base64Str string
	if err := json.Unmarshal(rawPayload, &base64Str); err != nil {
		return fmt.Errorf("invalid json string payload: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return fmt.Errorf("base64 decode failed: %w", err)
	}

	return seFunc(readerName, data)
}


func (s *CommandService) fetchCommands(apiUrl, token string) ([]TaxCoreCommand, error) {
	url := apiUrl
	if !strings.HasSuffix(url, "/commands") {
		url = strings.TrimRight(url, "/") + "/api/v3/sdc/commands"
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("TaxCoreAuthenticationToken", token)

	client := &http.Client{
		Transport: &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			TLSClientConfig: &tls.Config{
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch commands failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("api error %s: %s", resp.Status, string(body))
	}

	var commands []TaxCoreCommand
	if err := json.NewDecoder(resp.Body).Decode(&commands); err != nil {
		return nil, fmt.Errorf("json decode failed: %w", err)
	}

	return commands, nil
}

func (s *CommandService) notifyCommandProcessed(apiUrl, token, commandId string, success bool) error {
	url := apiUrl
	if !strings.HasSuffix(url, "/commands") {
		url = strings.TrimRight(url, "/") + "/api/v3/sdc/commands"
	}
	url = fmt.Sprintf("%s/%s", url, commandId)

	bodyStr := fmt.Sprintf("%v", success)
	req, _ := http.NewRequest("PUT", url, bytes.NewBufferString(bodyStr))

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("TaxCoreAuthenticationToken", token)

	client := &http.Client{
		Transport: &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			TLSClientConfig: &tls.Config{
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("api returned %s", resp.Status)
	}
	return nil
}
