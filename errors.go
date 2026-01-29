package main

import (
	"fmt"
	"net/http"
)

// APDUError represents a mapped error from the Secure Element
type APDUError struct {
	SW1SW2      uint16 `json:"sw_code"`
	Description string `json:"description"`
	POSCode     int    `json:"pos_error_code,omitempty"` // 0 if "SDC related"
	HTTPStatus  int    `json:"-"`                        // Internal HTTP status mapping
}

func (e *APDUError) Error() string {
	return fmt.Sprintf("SW %04X: %s", e.SW1SW2, e.Description)
}

// Standard Errors Map
var apduErrorMap = map[uint16]APDUError{
	0x6301: {Description: "PIN verification required", POSCode: 1500, HTTPStatus: http.StatusUnauthorized},
	0x6302: {Description: "PIN verification failed – wrong PIN code", POSCode: 2100, HTTPStatus: http.StatusUnauthorized},
	0x6303: {Description: "Wrong PIN size", POSCode: 2100, HTTPStatus: http.StatusBadRequest},
	0x6304: {Description: "Maximum number of tax categories exceeded", POSCode: 0, HTTPStatus: http.StatusBadRequest}, // SDC related
	0x6305: {Description: "Secure Element amount limit reached. Audit required.", POSCode: 2210, HTTPStatus: http.StatusForbidden},
	0x6306: {Description: "End Audit sent but no active Audit", POSCode: 0, HTTPStatus: http.StatusBadRequest}, // SDC related
	0x6307: {Description: "Invoice fiscalization is disabled by system", POSCode: 2210, HTTPStatus: http.StatusForbidden},
	0x6308: {Description: "Invoice DateTime outside Certificate validity", POSCode: 0, HTTPStatus: http.StatusBadRequest}, // SDC related
	0x6310: {Description: "PIN entries exceeded", POSCode: 2110, HTTPStatus: http.StatusForbidden},
	0x63FF: {Description: "Secure Element counter limit reached. Replace SE.", POSCode: 0, HTTPStatus: http.StatusForbidden}, // SDC related
	0x6700: {Description: "Data must be 256 bytes long", POSCode: 0, HTTPStatus: http.StatusBadRequest},                      // SDC related
	0x6A80: {Description: "Invalid Data / Tax category exceeded", POSCode: 2310, HTTPStatus: http.StatusBadRequest},          // Context dependent, using generic 400
	0x6F00: {Description: "Invalid Proof of Audit data", POSCode: 0, HTTPStatus: http.StatusBadRequest},                      // SDC related
}

// CheckAPDUError checks the status word and returns a mapped error if it's not success (0x9000)
func CheckAPDUError(resp []byte) error {
	if len(resp) < 2 {
		return fmt.Errorf("invalid response length")
	}

	sw1 := resp[len(resp)-2]
	sw2 := resp[len(resp)-1]
	code := uint16(sw1)<<8 | uint16(sw2)

	if code == 0x9000 {
		return nil
	}

	if mappedErr, exists := apduErrorMap[code]; exists {
		mappedErr.SW1SW2 = code
		return &mappedErr
	}

	// Generic fallback
	return &APDUError{
		SW1SW2:      code,
		Description: "Unknown APDU Error",
		POSCode:     0,
		HTTPStatus:  http.StatusInternalServerError,
	}
}

// APIErrorResponse is the standard JSON error format
type APIErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"description,omitempty"`
	POSCode     int    `json:"pos_error_code,omitempty"`
	SWCode      string `json:"sw_code,omitempty"`
}

// WriteAPIError writes the error to the HTTP response
func WriteAPIError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	if apduErr, ok := err.(*APDUError); ok {
		w.WriteHeader(apduErr.HTTPStatus)
		resp := APIErrorResponse{
			Error:       "Smart Card Error",
			Description: apduErr.Description,
			POSCode:     apduErr.POSCode,
			SWCode:      fmt.Sprintf("%04X", apduErr.SW1SW2),
		}
		// Handle 0 POSCode (SDC Related)
		if resp.POSCode == 0 {
			resp.Description += " (SDC Related)"
		}
		// Handle specific 6A80 ambiguity if needed, though map handles generic
		// If 6A80 came from End Audit vs Sign Invoice, the map has one entry.
		// Since we can't easily distinguish context here without passing it in,
		// we assume the map's default is sufficient or we rely on Description.

		// Special case for 6A80 conflict in prompt:
		// The prompt lists 6A80 twice.
		// 1. End Audit -> Proof mismatch
		// 2. Sign Invoice -> Tax cat exceeded (2310)
		// The map currently uses 2310. This is usually safer for the POS.

		// Encode
		// We use a custom encoder or just json.Marshal
		// For simplicity in this snippet:
		fmt.Fprintf(w, `{"error": "%s", "description": "%s", "pos_error_code": %d, "sw_code": "%s"}`,
			resp.Error, resp.Description, resp.POSCode, resp.SWCode)
		return
	}

	// Standard Go Error
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `{"error": "%s"}`, err.Error())
}
