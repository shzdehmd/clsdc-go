package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// DevMode flag
var DevMode bool

// responseWriter is a wrapper to capture the status code and body
type responseWriter struct {
	http.ResponseWriter
	status int
	body   *bytes.Buffer
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

// LoggingMiddleware wraps an http.Handler
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !DevMode {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		// 1. Capture Request Body
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = ioutil.ReadAll(r.Body)
			// Restore the body so the handler can read it
			r.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
		}

		// 2. Wrap Response Writer
		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			status:         http.StatusOK, // Default
			body:           new(bytes.Buffer),
		}

		// 3. Process Request
		next.ServeHTTP(wrappedWriter, r)

		duration := time.Since(start)

		// 4. Log Details
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("REQ: %s %s | IP: %s | Time: %v\n", r.Method, r.URL.Path, r.RemoteAddr, duration)
		if len(reqBody) > 0 {
			fmt.Printf("BODY: %s\n", string(reqBody))
		}
		fmt.Println("---")
		fmt.Printf("RES: Status %d\n", wrappedWriter.status)
		if wrappedWriter.body.Len() > 0 {
			// Limit log size if needed, but for JSON APIs usually fine
			fmt.Printf("BODY: %s\n", wrappedWriter.body.String())
		}
		fmt.Println("--------------------------------------------------------------------------------")
	})
}
