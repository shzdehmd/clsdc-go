package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

var storage *Storage
var cardSvc *CardService
var seSvc *SecureElementService
var authSvc *AuthService
var cmdSvc *CommandService
var timeSvc *TimeService

type SetReaderRequest struct {
	Reader string `json:"reader"`
}

type VerifyPinRequest struct {
	Pin string `json:"pin"`
}

func main() {
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

	cardSvc.SetOnCardRemoved(func(name string) {
		log.Printf("Card removed from %s, clearing session", name)
		seSvc.ClearSession()
	})

	cardSvc.StartWatcher()

	go func() {
		log.Println("Performing initial time sync...")
		if err := timeSvc.SyncTime(); err != nil {
			log.Printf("Initial Time Sync Warning: %v", err)
		}

		ticker := time.NewTicker(6 * time.Hour)
		for range ticker.C {
			if err := timeSvc.SyncTime(); err != nil {
				log.Printf("Periodic Time Sync Warning: %v", err)
			}
		}
	}()

	http.HandleFunc("/admin/readers", handleReaders)
	http.HandleFunc("/admin/card/version", handleCardVersion)
	http.HandleFunc("/admin/verify-pin", handleVerifyPin)
	http.HandleFunc("/admin/card/cert-params", handleCertParams)
	http.HandleFunc("/admin/card/pin-tries", handlePinTries)
	http.HandleFunc("/admin/card/last-signed-invoice", handleLastSignedInvoice)
	http.HandleFunc("/admin/card/taxpayer-info", handleTaxpayerInfo)
	http.HandleFunc("/admin/card/token", handleGetToken)
	http.HandleFunc("/admin/commands/sync", handleSyncCommands)

	port := ":9999"
	fmt.Printf("Server running at http://localhost%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}

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
	http.Error(w, `{"error": "No active reader selected"}`, http.StatusBadRequest)
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read card info: " + err.Error()})
		return
	}

	tokenResp, err := authSvc.GetToken(info.CommonName, info.ApiUrl)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Authentication failed: " + err.Error()})
		return
	}

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
