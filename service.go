package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ebfe/scard"
)

type ReaderInfo struct {
	Name        string `json:"name"`
	CardPresent bool   `json:"card_present"`
	IsActive    bool   `json:"is_active"`
}

type CardService struct {
	storage         *Storage
	mu              sync.RWMutex
	readers         map[string]*ReaderInfo
	preferredReader string
	onCardRemoved   func(string)
}

func NewCardService(storage *Storage) (*CardService, error) {
	cfg, err := storage.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	return &CardService{
		storage:         storage,
		readers:         make(map[string]*ReaderInfo),
		preferredReader: cfg.PreferredReader,
	}, nil
}

func (s *CardService) SetOnCardRemoved(callback func(string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onCardRemoved = callback
}

func (s *CardService) Close() {
}

func (s *CardService) SetActive(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.preferredReader = name
	return s.storage.Save(Config{PreferredReader: name})
}

func (s *CardService) GetReaders() []ReaderInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []ReaderInfo
	for _, r := range s.readers {
		isActive := (r.Name == s.preferredReader)
		list = append(list, ReaderInfo{
			Name:        r.Name,
			CardPresent: r.CardPresent,
			IsActive:    isActive,
		})
	}
	return list
}

func (s *CardService) StartWatcher() {
	go func() {
		log.Println("Service: Starting PC/SC Watcher...")

		for {
			ctx, err := scard.EstablishContext()
			if err != nil {
				log.Printf("Service: Failed to establish context: %v. Retrying in 2s...", err)
				time.Sleep(2 * time.Second)
				continue
			}

			log.Println("Service: Context established, monitoring hardware...")
			s.monitorLoop(ctx)

			ctx.Release()
			log.Println("Service: Context lost or reset. Restarting watcher in 1s...")

			s.mu.Lock()
			s.readers = make(map[string]*ReaderInfo)
			s.mu.Unlock()

			time.Sleep(1 * time.Second)
		}
	}()
}

func (s *CardService) monitorLoop(ctx *scard.Context) {
	pnpReaderName := "\\\\?PnP?\\Notification"

	pnpState := scard.ReaderState{
		Reader:       pnpReaderName,
		CurrentState: scard.StateUnaware,
	}

	if err := s.refreshReaders(ctx); err != nil {
		log.Printf("Service: Initial scan failed: %v", err)
		return
	}

	for {
		s.mu.RLock()
		var states []scard.ReaderState
		states = append(states, pnpState)

		for name, info := range s.readers {
			currentState := scard.StateEmpty
			if info.CardPresent {
				currentState = scard.StatePresent
			}
			states = append(states, scard.ReaderState{
				Reader:       name,
				CurrentState: currentState,
			})
		}
		s.mu.RUnlock()

		err := ctx.GetStatusChange(states, -1)
		if err != nil {
			log.Printf("Service: GetStatusChange error: %v", err)
			return
		}

		if states[0].EventState&scard.StateChanged != 0 {
			pnpState.CurrentState = states[0].EventState
			log.Println("Service: Hardware change detected")
			if err := s.refreshReaders(ctx); err != nil {
				log.Printf("Service: Failed to refresh readers: %v", err)
				return
			}
			continue
		}

		for i := 1; i < len(states); i++ {
			s.updateReaderState(states[i].Reader, states[i].EventState)
		}
	}
}

func (s *CardService) refreshReaders(ctx *scard.Context) error {
	readerNames, err := ctx.ListReaders()
	if err != nil {
		readerNames = []string{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	currentSet := make(map[string]bool)
	for _, name := range readerNames {
		currentSet[name] = true
		if _, exists := s.readers[name]; !exists {
			log.Printf("Reader Connected: %s", name)
			s.readers[name] = &ReaderInfo{Name: name, CardPresent: false}
		}
	}

	for name := range s.readers {
		if !currentSet[name] {
			log.Printf("Reader Disconnected: %s", name)
			delete(s.readers, name)
			if s.onCardRemoved != nil {
				s.onCardRemoved(name)
			}
		}
	}
	return nil
}

func (s *CardService) updateReaderState(name string, state scard.StateFlag) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if reader, exists := s.readers[name]; exists {
		isPresent := state&scard.StatePresent != 0
		if reader.CardPresent != isPresent {
			reader.CardPresent = isPresent
			if isPresent {
				log.Printf("Card INSERTED: %s", name)
			} else {
				log.Printf("Card REMOVED: %s", name)
				if s.onCardRemoved != nil {
					s.onCardRemoved(name)
				}
			}
		}
	}
}
