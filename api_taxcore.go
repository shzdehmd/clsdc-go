package main

import (
	"net/http"
)

func RegisterTaxCoreRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v3/environment-parameters", handleEnvironmentParameters)
	mux.HandleFunc("/api/v3/attention", handleAttention)
}

func handleEnvironmentParameters(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	envConfig, err := storage.GetRawJSON(TaxCoreConfigFile)
	if err != nil {
		http.Error(w, "Configuration not found", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(envConfig)
}

func handleAttention(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	readers := cardSvc.GetReaders()
	var activeReader *ReaderInfo
	for _, r := range readers {
		if r.IsActive {
			activeReader = &r
			break
		}
	}

	if activeReader == nil || !activeReader.CardPresent {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error": "Secure Element not present"}`))
		return
	}

	if !seSvc.IsSessionActive() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized) // 401
		w.Write([]byte(`{"error": "PIN verification required"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
}
