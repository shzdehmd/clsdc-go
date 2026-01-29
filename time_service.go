package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/beevik/ntp"
)

const TimeServerFile = "time_server.json"
const DefaultNtpServer = "pool.ntp.org"

type TimeService struct{}

func NewTimeService() *TimeService {
	return &TimeService{}
}

// SyncTime reads the configured NTP server and updates the system clock
func (s *TimeService) SyncTime() error {
	// 1. Get NTP Server URL
	ntpServer := DefaultNtpServer

	data, err := ioutil.ReadFile(TimeServerFile)
	if err == nil && len(data) > 0 {
		// Clean up the string (remove quotes or whitespace)
		savedUrl := strings.Trim(string(data), "\" \n\r\t")
		if savedUrl != "" {
			ntpServer = savedUrl
		}
	}

	log.Printf("TimeService: Syncing with %s...", ntpServer)

	// 2. Query NTP
	response, err := ntp.Query(ntpServer)
	if err != nil {
		return fmt.Errorf("failed to query NTP server: %w", err)
	}

	// Calculate the correct time (Local system time + Offset)
	now := time.Now().Add(response.ClockOffset)

	log.Printf("TimeService: NTP Time is %s (Offset: %v)", now.Format(time.RFC3339), response.ClockOffset)

	// 3. Set System Time
	// Note: This requires Administrator privileges
	if err := setSystemTime(now); err != nil {
		return fmt.Errorf("failed to set system clock (run as admin?): %w", err)
	}

	log.Println("TimeService: System clock updated successfully.")
	return nil
}

// setSystemTime updates the Windows OS clock
func setSystemTime(newTime time.Time) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procSetSystemTime := kernel32.NewProc("SetSystemTime")

	// Windows SetSystemTime expects UTC
	t := newTime.UTC()

	type SYSTEMTIME struct {
		wYear         uint16
		wMonth        uint16
		wDayOfWeek    uint16
		wDay          uint16
		wHour         uint16
		wMinute       uint16
		wSecond       uint16
		wMilliseconds uint16
	}

	sysTime := SYSTEMTIME{
		wYear:         uint16(t.Year()),
		wMonth:        uint16(t.Month()),
		wDayOfWeek:    uint16(t.Weekday()),
		wDay:          uint16(t.Day()),
		wHour:         uint16(t.Hour()),
		wMinute:       uint16(t.Minute()),
		wSecond:       uint16(t.Second()),
		wMilliseconds: uint16(t.Nanosecond() / 1000000),
	}

	ret, _, err := procSetSystemTime.Call(uintptr(unsafe.Pointer(&sysTime)))
	if ret == 0 {
		return err
	}
	return nil
}
