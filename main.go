package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// --- Globals ---
var storage *Storage
var cardSvc *CardService
var seSvc *SecureElementService
var authSvc *AuthService
var cmdSvc *CommandService
var timeSvc *TimeService

// --- Request/Response Structs ---

type SetReaderRequest struct {
	Reader string `json:"reader"`
}

type VerifyPinRequest struct {
	Pin string `json:"pin"`
}

// Heartbeat Enums & Structs
type FiscalStatus int

const (
	StatusNoReader    FiscalStatus = 0
	StatusCardMissing FiscalStatus = 1
	StatusPinRequired FiscalStatus = 2
	StatusReady       FiscalStatus = 3
)

type CardMetadata struct {
	Url         string `json:"url"`
	Tin         string `json:"tin"`
	CompanyName string `json:"companyName"`
	Uid         string `json:"uid"`
}

type AmountStatusResponse struct {
	CurrentTotal  float64 `json:"currentTotal"`
	Limit         float64 `json:"limit"`
	AuditRequired bool    `json:"auditRequired"`
}

type HeartbeatResponse struct {
	Status       FiscalStatus          `json:"status"`
	ReaderName   string                `json:"readerName,omitempty"`
	CardPresent  bool                  `json:"cardPresent"`
	PinTriesLeft int                   `json:"pinTriesLeft"`
	SeVersion    string                `json:"seVersion,omitempty"`
	AmountStatus *AmountStatusResponse `json:"amountStatus,omitempty"`
	Metadata     *CardMetadata         `json:"metadata,omitempty"`
}

type ConfigResponse struct {
	TaxRates        json.RawMessage `json:"taxRates"`
	Environment     json.RawMessage `json:"environment"`
	VerificationUrl string          `json:"verificationUrl"`
	Reader          string          `json:"reader"`
}

// --- Main Entry Point ---

func main() {
	// 1. Parse Flags
	flag.BoolVar(&DevMode, "dev", false, "Enable development logging")
	flag.Parse()

	if DevMode {
		log.Println("Development Mode Enabled: Logging all HTTP traffic")
	}

	// 2. Initialize Services
	storage = &Storage{}

	var err error
	cardSvc, err = NewCardService(storage)
	if err != nil {
		log.Fatalf("Failed to start card service: %v", err)
	}

	seSvc = NewSecureElementService()
	authSvc = NewAuthService()
	timeSvc = NewTimeService()
	cmdSvc = NewCommandService(storage, seSvc, cardSvc, timeSvc)

	// 3. Setup Callbacks
	cardSvc.SetOnCardRemoved(func(name string) {
		log.Printf("Card removed from %s, clearing session", name)
		seSvc.ClearSession()
	})

	// 4. Start Background Watcher
	cardSvc.StartWatcher()

	// 5. Start Background Tasks (Time Sync & Heartbeat)
	go func() {
		// Initial Time Sync
		log.Println("Performing initial time sync...")
		if err := timeSvc.SyncTime(); err != nil {
			log.Printf("Initial Time Sync Warning: %v", err)
		}

		timeTicker := time.NewTicker(6 * time.Hour)
		statusTicker := time.NewTicker(5 * time.Minute)

		for {
			select {
			case <-timeTicker.C:
				if err := timeSvc.SyncTime(); err != nil {
					log.Printf("Periodic Time Sync Warning: %v", err)
				}
			case <-statusTicker.C:
				// Only try if we have a token
				cfg, _ := storage.Load()
				if cfg.Token != "" {
					log.Println("Sending Online Status Heartbeat...")
					if err := cmdSvc.NotifyOnlineStatus(); err != nil {
						log.Printf("Heartbeat Warning: %v", err)
					}
				}
			}
		}
	}()

	// 6. Setup Router
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/readers", handleReaders)
	mux.HandleFunc("/admin/card/version", handleCardVersion)
	mux.HandleFunc("/admin/verify-pin", handleVerifyPin)
	mux.HandleFunc("/admin/card/cert-params", handleCertParams)
	mux.HandleFunc("/admin/card/pin-tries", handlePinTries)
	mux.HandleFunc("/admin/card/last-signed-invoice", handleLastSignedInvoice)
	mux.HandleFunc("/admin/card/taxpayer-info", handleTaxpayerInfo)
	mux.HandleFunc("/admin/card/token", handleGetToken)
	mux.HandleFunc("/admin/commands/sync", handleSyncCommands)
	mux.HandleFunc("/admin/card/amount-status", handleAmountStatus)
	mux.HandleFunc("/admin/heartbeat", handleHeartbeat)
	mux.HandleFunc("/admin/config", handleGetConfig)

	// 7. Wrap with Middleware
	handler := LoggingMiddleware(mux)

	port := ":9999"
	fmt.Printf("Server running at http://localhost%s\n", port)
	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatal(err)
	}
}

// --- HTTP Handlers ---

func handleReaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		readers := cardSvc.GetReaders()
		json.NewEncoder(w).Encode(readers)

	case http.MethodPost:
		var req SetReaderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Reader == "" {
			http.Error(w, "Reader name required", http.StatusBadRequest)
			return
		}

		if err := cardSvc.SetActive(req.Reader); err != nil {
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		readers := cardSvc.GetReaders()
		json.NewEncoder(w).Encode(readers)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getActiveReader(w http.ResponseWriter) string {
	readers := cardSvc.GetReaders()
	for _, reader := range readers {
		if reader.IsActive {
			return reader.Name
		}
	}
	// Return generic error if no reader selected
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": "No active reader selected"})
	return ""
}

func handleCardVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeReader := getActiveReader(w)
	if activeReader == "" {
		return
	}

	version, err := seSvc.GetVersion(activeReader)
	if err != nil {
		WriteAPIError(w, err)
		return
	}

	json.NewEncoder(w).Encode(version)
}

func handleVerifyPin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyPinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Pin == "" {
		http.Error(w, `{"error": "PIN required"}`, http.StatusBadRequest)
		return
	}

	activeReader := getActiveReader(w)
	if activeReader == "" {
		return
	}

	sw, err := seSvc.VerifyPin(activeReader, req.Pin)
	if err != nil {
		WriteAPIError(w, err)
		return
	}

	resp := map[string]interface{}{
		"sw":      fmt.Sprintf("%04X", sw),
		"success": sw == 0x9000,
	}
	json.NewEncoder(w).Encode(resp)
}

func handleCertParams(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeReader := getActiveReader(w)
	if activeReader == "" {
		return
	}

	params, err := seSvc.GetCertParams(activeReader)
	if err != nil {
		WriteAPIError(w, err)
		return
	}

	json.NewEncoder(w).Encode(params)
}

func handlePinTries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeReader := getActiveReader(w)
	if activeReader == "" {
		return
	}

	tries, err := seSvc.GetPinTries(activeReader)
	if err != nil {
		WriteAPIError(w, err)
		return
	}

	json.NewEncoder(w).Encode(map[string]int{"tries_left": tries})
}

func handleLastSignedInvoice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeReader := getActiveReader(w)
	if activeReader == "" {
		return
	}

	invoice, err := seSvc.GetLastSignedInvoice(activeReader)
	if err != nil {
		WriteAPIError(w, err)
		return
	}

	json.NewEncoder(w).Encode(invoice)
}

func handleTaxpayerInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeReader := getActiveReader(w)
	if activeReader == "" {
		return
	}

	info, err := seSvc.GetTaxpayerInfo(activeReader)
	if err != nil {
		WriteAPIError(w, err)
		return
	}

	json.NewEncoder(w).Encode(info)
}

func handleGetToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeReader := getActiveReader(w)
	if activeReader == "" {
		return
	}

	info, err := seSvc.GetTaxpayerInfo(activeReader)
	if err != nil {
		WriteAPIError(w, err)
		return
	}

	tokenResp, err := authSvc.GetToken(info.CommonName, info.ApiUrl)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Authentication failed: " + err.Error()})
		return
	}

	// Save to storage
	cfg, err := storage.Load()
	if err == nil {
		cfg.Token = tokenResp.Token
		cfg.TokenExpiresAt = tokenResp.ExpiresAt
		storage.Save(cfg)
	}

	json.NewEncoder(w).Encode(tokenResp)
}

func handleSyncCommands(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	results, err := cmdSvc.SyncCommands()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(results)
}

func handleAmountStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeReader := getActiveReader(w)
	if activeReader == "" {
		return
	}

	status, err := seSvc.GetAmountStatus(activeReader)
	if err != nil {
		WriteAPIError(w, err)
		return
	}

	json.NewEncoder(w).Encode(status)
}

func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := HeartbeatResponse{
		Status:      StatusNoReader,
		CardPresent: false,
	}

	// 1. Check Reader
	readers := cardSvc.GetReaders()
	var activeReader *ReaderInfo
	for _, reader := range readers {
		if reader.IsActive {
			activeReader = &reader
			break
		}
	}

	if activeReader == nil {
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp.ReaderName = activeReader.Name
	resp.CardPresent = activeReader.CardPresent

	if !activeReader.CardPresent {
		resp.Status = StatusCardMissing
		json.NewEncoder(w).Encode(resp)
		return
	}

	// 2. Get Card Data
	data, err := seSvc.GetHeartbeatData(activeReader.Name)
	if err != nil {
		// Communication failed, treat as missing or error
		resp.Status = StatusCardMissing
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp.PinTriesLeft = data.PinTries
	resp.SeVersion = data.SeVersion

	if !data.IsVerified {
		resp.Status = StatusPinRequired
		json.NewEncoder(w).Encode(resp)
		return
	}

	// 3. Ready State
	resp.Status = StatusReady

	// Map Amount Status
	if data.AmountStatus != nil {
		current, _ := strconv.ParseFloat(data.AmountStatus.SumAmount, 64)
		limit, _ := strconv.ParseFloat(data.AmountStatus.LimitAmount, 64)

		resp.AmountStatus = &AmountStatusResponse{
			CurrentTotal:  current,
			Limit:         limit,
			AuditRequired: current >= limit,
		}
	}

	// Map Metadata
	if data.TaxpayerInfo != nil {
		uid := ""
		if data.CertParams != nil {
			uid = data.CertParams.UID
		} else {
			uid = data.TaxpayerInfo.SerialNumber // Fallback
		}

		resp.Metadata = &CardMetadata{
			Url:         data.TaxpayerInfo.ApiUrl,
			Tin:         data.TaxpayerInfo.TaxpayerID,
			CompanyName: data.TaxpayerInfo.CommonName,
			Uid:         uid,
		}
	}

	json.NewEncoder(w).Encode(resp)
}

func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Load Main Config (for Reader)
	mainCfg, err := storage.Load()
	if err != nil {
		mainCfg = Config{}
	}

	// 2. Load Raw JSON Data
	taxRates, _ := storage.GetRawJSON(TaxRatesFile)
	envConfig, _ := storage.GetRawJSON(TaxCoreConfigFile)

	// 3. Load and Clean Verification URL
	verUrl, _ := storage.GetVerificationUrl()

	// 4. Construct Response
	resp := ConfigResponse{
		TaxRates:        taxRates,
		Environment:     envConfig,
		VerificationUrl: verUrl,
		Reader:          mainCfg.PreferredReader,
	}

	json.NewEncoder(w).Encode(resp)
}
