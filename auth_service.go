//go:build windows

package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32 = windows.NewLazySystemDLL("crypt32.dll")
	ncrypt  = windows.NewLazySystemDLL("ncrypt.dll")

	procCertOpenSystemStoreW              = crypt32.NewProc("CertOpenSystemStoreW")
	procCertFindCertificateInStore        = crypt32.NewProc("CertFindCertificateInStore")
	procCryptAcquireCertificatePrivateKey = crypt32.NewProc("CryptAcquireCertificatePrivateKey")
	procNCryptSignHash                    = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject                  = ncrypt.NewProc("NCryptFreeObject")
)

const (
	CERT_STORE_PROV_SYSTEM             = 10
	CERT_SYSTEM_STORE_CURRENT_USER     = 1 << 16
	PKCS_7_ASN_ENCODING                = 65536
	X509_ASN_ENCODING                  = 1
	CERT_FIND_ANY                      = 0
	CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000
	CRYPT_ACQUIRE_CACHE_FLAG           = 0x00000001
	BCRYPT_PAD_PKCS1                   = 0x00000002
)

type AuthService struct{}

type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

func NewAuthService() *AuthService {
	return &AuthService{}
}

func (s *AuthService) GetToken(certCommonName string, apiUrl string) (*TokenResponse, error) {
	if certCommonName == "" || certCommonName == "Not Applicable" {
		return nil, fmt.Errorf("invalid certificate common name")
	}
	if apiUrl == "" || apiUrl == "Not Applicable" {
		return nil, fmt.Errorf("invalid api url")
	}

	cert, keyHandle, err := s.findCertAndKey(certCommonName)
	if err != nil {
		return nil, fmt.Errorf("error finding cert in windows store: %w", err)
	}
	defer s.freeKey(keyHandle)

	signer := &WindowsSigner{
		Pub:       cert.PublicKey,
		KeyHandle: keyHandle,
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:  []tls.Certificate{tlsCert},
				MinVersion:    tls.VersionTLS12,
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
		},
	}

	tokenUrl := apiUrl
	if !strings.HasSuffix(tokenUrl, "/token") {
		tokenUrl = strings.TrimRight(tokenUrl, "/") + "/api/v3/sdc/token"
	}

	req, _ := http.NewRequest("GET", tokenUrl, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("api returned %s: %s", resp.Status, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Token == "" {
		return nil, fmt.Errorf("response did not contain 'token' field")
	}

	return &tokenResp, nil
}

type WindowsSigner struct {
	Pub       crypto.PublicKey
	KeyHandle uintptr
}

func (w *WindowsSigner) Public() crypto.PublicKey {
	return w.Pub
}

func (w *WindowsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algoName, _ := windows.UTF16PtrFromString("SHA256")
	padInfo := struct {
		pszAlgId *uint16
		pbPC     uintptr
		cbPC     uint32
	}{
		pszAlgId: algoName,
		pbPC:     0,
		cbPC:     0,
	}

	var signatureLen uint32
	r, _, _ := procNCryptSignHash.Call(
		w.KeyHandle,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&signatureLen)),
		BCRYPT_PAD_PKCS1,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash (size) failed: %X", r)
	}

	signature := make([]byte, signatureLen)
	r, _, _ = procNCryptSignHash.Call(
		w.KeyHandle,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(signatureLen),
		uintptr(unsafe.Pointer(&signatureLen)),
		BCRYPT_PAD_PKCS1,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash (sign) failed: %X", r)
	}

	return signature[:signatureLen], nil
}

func (s *AuthService) findCertAndKey(nameFilter string) (*x509.Certificate, uintptr, error) {
	storeName, _ := windows.UTF16PtrFromString("MY")
	store, _, _ := procCertOpenSystemStoreW.Call(0, uintptr(unsafe.Pointer(storeName)))
	if store == 0 {
		return nil, 0, fmt.Errorf("failed to open MY store")
	}

	var certContext *windows.CertContext
	for {
		ptr, _, _ := procCertFindCertificateInStore.Call(
			store,
			PKCS_7_ASN_ENCODING|X509_ASN_ENCODING,
			0,
			CERT_FIND_ANY,
			0,
			uintptr(unsafe.Pointer(certContext)),
		)
		if ptr == 0 {
			break
		}
		certContext = (*windows.CertContext)(unsafe.Pointer(ptr))

		buf := make([]byte, certContext.Length)
		copy(buf, (*[1 << 20]byte)(unsafe.Pointer(certContext.EncodedCert))[:certContext.Length:certContext.Length])

		x509Cert, err := x509.ParseCertificate(buf)
		if err != nil {
			continue
		}

		if strings.Contains(x509Cert.Subject.CommonName, nameFilter) {
			var keyHandle uintptr
			var spec uint32
			var freeBool int32

			r, _, _ := procCryptAcquireCertificatePrivateKey.Call(
				uintptr(unsafe.Pointer(certContext)),
				CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_CACHE_FLAG,
				0,
				uintptr(unsafe.Pointer(&keyHandle)),
				uintptr(unsafe.Pointer(&spec)),
				uintptr(unsafe.Pointer(&freeBool)),
			)

			if r != 1 {
				return nil, 0, fmt.Errorf("failed to acquire private key (is card inserted?)")
			}

			return x509Cert, keyHandle, nil
		}
	}

	return nil, 0, fmt.Errorf("certificate not found")
}

func (s *AuthService) freeKey(handle uintptr) {
	if handle != 0 {
		procNCryptFreeObject.Call(handle)
	}
}
