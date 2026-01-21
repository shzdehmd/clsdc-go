package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ebfe/scard"
)

type SEVersion struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
	Patch uint32 `json:"patch"`
}

type CertParams struct {
	UID       string `json:"uid"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

type LastSignedInvoice struct {
	DateTime              string `json:"date_time"`
	TaxpayerID            string `json:"taxpayer_id"`
	BuyerID               string `json:"buyer_id"`
	InvoiceType           string `json:"invoice_type"`
	TransactionType       string `json:"transaction_type"`
	InvoiceAmount         string `json:"invoice_amount"`
	SaleRefundCounter     uint32 `json:"sale_refund_counter"`
	TotalCounter          uint32 `json:"total_counter"`
	EncryptedInternalData string `json:"encrypted_internal_data"`
	Signature             string `json:"signature"`
}

type TaxpayerInfo struct {
	CommonName           string `json:"common_name"`
	SerialNumber         string `json:"serial_number"`
	GivenName            string `json:"given_name"`
	Surname              string `json:"surname"`
	OrganizationUnit     string `json:"organization_unit"`
	Organization         string `json:"organization"`
	Street               string `json:"street"`
	City                 string `json:"city"`
	State                string `json:"state"`
	Country              string `json:"country"`
	TaxpayerID           string `json:"taxpayer_id"`
	ApiUrl               string `json:"api_url"`
	CertificateValidTo   string `json:"certificate_valid_to"`
}

type SecureElementService struct {
	mu         sync.Mutex
	isVerified bool
	cachedPin  []byte
	cachedInfo *TaxpayerInfo
}

func NewSecureElementService() *SecureElementService {
	return &SecureElementService{}
}

func (s *SecureElementService) ClearSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isVerified = false
	s.cachedPin = nil
	s.cachedInfo = nil
}

func (s *SecureElementService) connectAndSelect(readerName string) (*scard.Context, *scard.Card, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to establish context: %w", err)
	}

	card, err := ctx.Connect(readerName, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		ctx.Release()
		return nil, nil, fmt.Errorf("failed to connect to card: %w", err)
	}

	if err := card.BeginTransaction(); err != nil {
		card.Disconnect(scard.LeaveCard)
		ctx.Release()
		return nil, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	apduSelect := make([]byte, 0)
	apduSelect = append(apduSelect, CmdSelect...)
	apduSelect = append(apduSelect, byte(len(SecureElementAID)))
	apduSelect = append(apduSelect, SecureElementAID...)
	apduSelect = append(apduSelect, 0x00)

	resp, err := card.Transmit(apduSelect)
	if err != nil {
		s.cleanup(ctx, card)
		return nil, nil, fmt.Errorf("failed to transmit SELECT: %w", err)
	}

	if !isSuccess(resp) {
		s.cleanup(ctx, card)
		return nil, nil, fmt.Errorf("SELECT failed with SW: %X", resp[len(resp)-2:])
	}

	s.mu.Lock()
	pin := s.cachedPin
	verified := s.isVerified
	s.mu.Unlock()

	if verified && len(pin) > 0 {
		apduVerify := make([]byte, 0)
		apduVerify = append(apduVerify, CmdVerifyPinHeader...)
		apduVerify = append(apduVerify, byte(len(pin)))
		apduVerify = append(apduVerify, pin...)

		resp, err := card.Transmit(apduVerify)
		if err != nil || !isSuccess(resp) {
			s.ClearSession()
			s.cleanup(ctx, card)
			return nil, nil, fmt.Errorf("auto-verification with cached PIN failed (Session cleared)")
		}
	}

	return ctx, card, nil
}

func (s *SecureElementService) cleanup(ctx *scard.Context, card *scard.Card) {
	if card != nil {
		card.EndTransaction(scard.LeaveCard)
		card.Disconnect(scard.LeaveCard)
	}
	if ctx != nil {
		ctx.Release()
	}
}

func (s *SecureElementService) VerifyPin(readerName string, pin string) (int, error) {
	if readerName == "" {
		return 0, fmt.Errorf("no active reader selected")
	}

	ctx, card, err := s.connectAndSelect(readerName)
	if err != nil {
		return 0, err
	}
	defer s.cleanup(ctx, card)

	pinBytes := []byte(pin)
	apduVerify := make([]byte, 0)
	apduVerify = append(apduVerify, CmdVerifyPinHeader...)
	apduVerify = append(apduVerify, byte(len(pinBytes)))
	apduVerify = append(apduVerify, pinBytes...)

	resp, err := card.Transmit(apduVerify)
	if err != nil {
		return 0, fmt.Errorf("failed to transmit VERIFY: %w", err)
	}

	sw := 0
	if len(resp) >= 2 {
		sw = (int(resp[len(resp)-2]) << 8) | int(resp[len(resp)-1])
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if sw == 0x9000 {
		s.isVerified = true
		s.cachedPin = pinBytes
	} else {
		s.isVerified = false
		s.cachedPin = nil
	}

	return sw, nil
}

func (s *SecureElementService) GetVersion(readerName string) (*SEVersion, error) {
	if readerName == "" {
		return nil, fmt.Errorf("no active reader selected")
	}

	ctx, card, err := s.connectAndSelect(readerName)
	if err != nil {
		return nil, err
	}
	defer s.cleanup(ctx, card)

	resp, err := card.Transmit(CmdGetVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit GET VERSION: %w", err)
	}

	if !isSuccess(resp) {
		return nil, fmt.Errorf("GET VERSION failed with SW: %X", resp[len(resp)-2:])
	}

	if len(resp) < 14 {
		return nil, fmt.Errorf("invalid response length: %d", len(resp))
	}

	version := &SEVersion{
		Major: binary.BigEndian.Uint32(resp[0:4]),
		Minor: binary.BigEndian.Uint32(resp[4:8]),
		Patch: binary.BigEndian.Uint32(resp[8:12]),
	}

	return version, nil
}

func (s *SecureElementService) GetCertParams(readerName string) (*CertParams, error) {
	if readerName == "" {
		return nil, fmt.Errorf("no active reader selected")
	}

	ctx, card, err := s.connectAndSelect(readerName)
	if err != nil {
		return nil, err
	}
	defer s.cleanup(ctx, card)

	resp, err := card.Transmit(CmdGetCertParams)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit GET CERT PARAMS: %w", err)
	}

	if !isSuccess(resp) {
		return nil, fmt.Errorf("GET CERT PARAMS failed with SW: %X", resp[len(resp)-2:])
	}

	if len(resp) < 26 {
		return nil, fmt.Errorf("invalid response length: %d", len(resp))
	}

	uidBytes := resp[0:8]
	notBeforeMs := binary.BigEndian.Uint64(resp[8:16])
	notAfterMs := binary.BigEndian.Uint64(resp[16:24])

	tBefore := time.UnixMilli(int64(notBeforeMs))
	tAfter := time.UnixMilli(int64(notAfterMs))

	params := &CertParams{
		UID:       string(uidBytes),
		NotBefore: tBefore.Format(time.RFC3339),
		NotAfter:  tAfter.Format(time.RFC3339),
	}

	return params, nil
}

func (s *SecureElementService) GetPinTries(readerName string) (int, error) {
	if readerName == "" {
		return 0, fmt.Errorf("no active reader selected")
	}

	ctx, card, err := s.connectAndSelect(readerName)
	if err != nil {
		return 0, err
	}
	defer s.cleanup(ctx, card)

	resp, err := card.Transmit(CmdGetPinTries)
	if err != nil {
		return 0, fmt.Errorf("failed to transmit GET PIN TRIES: %w", err)
	}

	if !isSuccess(resp) {
		return 0, fmt.Errorf("GET PIN TRIES failed with SW: %X", resp[len(resp)-2:])
	}

	if len(resp) < 3 {
		return 0, fmt.Errorf("invalid response length")
	}

	tries := int(resp[0])
	return tries, nil
}

func (s *SecureElementService) GetLastSignedInvoice(readerName string) (*LastSignedInvoice, error) {
	if readerName == "" {
		return nil, fmt.Errorf("no active reader selected")
	}

	ctx, card, err := s.connectAndSelect(readerName)
	if err != nil {
		return nil, err
	}
	defer s.cleanup(ctx, card)

	resp, err := card.Transmit(CmdGetLastSignedInvoice)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit GET LAST SIGNED INVOICE: %w", err)
	}

	if !isSuccess(resp) {
		return nil, fmt.Errorf("GET LAST SIGNED INVOICE failed with SW: %X", resp[len(resp)-2:])
	}

	dataLen := len(resp) - 2
	if dataLen < 321 {
		return nil, fmt.Errorf("response too short: %d", dataLen)
	}

	data := resp[:dataLen]

	dateMs := binary.BigEndian.Uint64(data[0:8])
	dateObj := time.UnixMilli(int64(dateMs))

	taxpayerID := strings.Trim(string(data[8:28]), "\x00")
	buyerID := strings.Trim(string(data[28:48]), "\x00")

	invType := data[48]
	invTypeStr := "Unknown"
	switch invType {
	case 0:
		invTypeStr = "Normal"
	case 1:
		invTypeStr = "Proforma"
	case 2:
		invTypeStr = "Copy"
	case 3:
		invTypeStr = "Training"
	}

	txType := data[49]
	txTypeStr := "Unknown"
	switch txType {
	case 0:
		txTypeStr = "Sale"
	case 1:
		txTypeStr = "Refund"
	}

	amtBytes := []byte{0x00}
	amtBytes = append(amtBytes, data[50:57]...)
	rawAmt := binary.BigEndian.Uint64(amtBytes)
	readableAmt := fmt.Sprintf("%.4f", float64(rawAmt)/10000.0)

	invoice := &LastSignedInvoice{
		DateTime:          dateObj.Format(time.RFC3339),
		TaxpayerID:        taxpayerID,
		BuyerID:           buyerID,
		InvoiceType:       invTypeStr,
		TransactionType:   txTypeStr,
		InvoiceAmount:     readableAmt,
		SaleRefundCounter: binary.BigEndian.Uint32(data[57:61]),
		TotalCounter:      binary.BigEndian.Uint32(data[61:65]),
	}

	signatureLen := 256
	encryptedDataLen := dataLen - 65 - signatureLen

	if encryptedDataLen < 0 {
		return nil, fmt.Errorf("invalid data structure")
	}

	invoice.EncryptedInternalData = hex.EncodeToString(data[65 : 65+encryptedDataLen])
	invoice.Signature = hex.EncodeToString(data[65+encryptedDataLen : 65+encryptedDataLen+signatureLen])

	return invoice, nil
}

func (s *SecureElementService) GetTaxpayerInfo(readerName string) (*TaxpayerInfo, error) {
	s.mu.Lock()
	if s.cachedInfo != nil {
		info := s.cachedInfo
		s.mu.Unlock()
		return info, nil
	}
	s.mu.Unlock()

	if readerName == "" {
		return nil, fmt.Errorf("no active reader selected")
	}

	ctx, card, err := s.connectAndSelect(readerName)
	if err != nil {
		return nil, err
	}
	defer s.cleanup(ctx, card)

	resp, err := card.Transmit(CmdExportCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit EXPORT CERTIFICATE: %w", err)
	}

	if !isSuccess(resp) {
		return nil, fmt.Errorf("EXPORT CERTIFICATE failed with SW: %X", resp[len(resp)-2:])
	}

	certBytes := resp[:len(resp)-2]
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	info := &TaxpayerInfo{
		CommonName:         "Not Applicable",
		SerialNumber:       "Not Applicable",
		GivenName:          "Not Applicable",
		Surname:            "Not Applicable",
		OrganizationUnit:   "Not Applicable",
		Organization:       "Not Applicable",
		Street:             "Not Applicable",
		City:               "Not Applicable",
		State:              "Not Applicable",
		Country:            "Not Applicable",
		TaxpayerID:         "Not Applicable",
		ApiUrl:             "Not Applicable",
		CertificateValidTo: cert.NotAfter.Format(time.RFC3339),
	}

	for _, name := range cert.Subject.Names {
		val, ok := name.Value.(string)
		if !ok {
			continue
		}
		switch {
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}):
			info.CommonName = val
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 5}):
			info.SerialNumber = val
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 42}):
			info.GivenName = val
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 4}):
			info.Surname = val
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 11}):
			info.OrganizationUnit = val
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 10}):
			info.Organization = val
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 9}):
			info.Street = val
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 7}):
			info.City = val
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 8}):
			info.State = val
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 6}):
			info.Country = val
		}
	}

	ekuOID := asn1.ObjectIdentifier{2, 5, 29, 37}
	var tinOID []int
	var urlOID []int

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ekuOID) {
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &oids); err == nil {
				for _, oid := range oids {
					if len(oid) >= 11 &&
					   oid[0] == 1 && oid[1] == 3 && oid[2] == 6 && oid[3] == 1 &&
					   oid[4] == 4 && oid[5] == 1 && oid[6] == 49952 {

						env1 := oid[len(oid)-4]
						env2 := oid[len(oid)-3]

						// TIN ends in .6
						tinOID = []int{1, 3, 6, 1, 4, 1, 49952, env1, env2, 6}
						// URL ends in .5
						urlOID = []int{1, 3, 6, 1, 4, 1, 49952, env1, env2, 5}
						break
					}
				}
			}
		}
	}

	if len(tinOID) > 0 {
		targetTIN := asn1.ObjectIdentifier(tinOID)
		targetURL := asn1.ObjectIdentifier(urlOID)

		for _, ext := range cert.Extensions {
			if ext.Id.Equal(targetTIN) {
				var valBytes []byte
				if _, err := asn1.Unmarshal(ext.Value, &valBytes); err == nil {
					info.TaxpayerID = string(valBytes)
				} else {
					info.TaxpayerID = string(ext.Value)
				}
			}
			if ext.Id.Equal(targetURL) {
				var valBytes []byte
				if _, err := asn1.Unmarshal(ext.Value, &valBytes); err == nil {
					info.ApiUrl = string(valBytes)
				} else {
					info.ApiUrl = string(ext.Value)
				}
			}
		}
	}

	s.mu.Lock()
	s.cachedInfo = info
	s.mu.Unlock()

	return info, nil
}

func isSuccess(resp []byte) bool {
	if len(resp) < 2 {
		return false
	}
	sw1 := resp[len(resp)-2]
	sw2 := resp[len(resp)-1]
	return sw1 == 0x90 && sw2 == 0x00
}
