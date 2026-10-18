// language: Go, file: internal/store/sqlite_cache.go, target: Go 1.22+, Cross-Platform
package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CachedTarget struct {
	TargetID  string             `json:"target_id"`
	BaseURL   string             `json:"base_url"`
	WAFVendor string             `json:"waf_vendor"`
	CPEs      map[string]float64 `json:"cpes"`
	Timestamp int64              `json:"timestamp"`
}

type LocalStore struct {
	mu      sync.Mutex
	Targets map[string]CachedTarget `json:"targets"`
}

func NewLocalStore() *LocalStore {
	return &LocalStore{
		Targets: make(map[string]CachedTarget),
	}
}

func (s *LocalStore) RecordTarget(id, baseURL, wafVendor string, cpes map[string]float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Targets[id] = CachedTarget{
		TargetID:  id,
		BaseURL:   baseURL,
		WAFVendor: wafVendor,
		CPEs:      cpes,
		Timestamp: time.Now().Unix(),
	}
}

// Flush writes both the indexed JSON state cache and the deterministic SQLite 3 WAL transaction dump.
func (s *LocalStore) Flush(outDir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	jsonBytes, err := json.MarshalIndent(s.Targets, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "kinetix_cache.json"), jsonBytes, 0644); err != nil {
		return err
	}

	var sqlBuf bytes.Buffer
	sqlBuf.WriteString("PRAGMA journal_mode = WAL;\nPRAGMA synchronous = NORMAL;\n")
	sqlBuf.WriteString("CREATE TABLE IF NOT EXISTS targets (target_id TEXT PRIMARY KEY, base_url TEXT, waf_vendor TEXT, created_at INTEGER);\n")
	sqlBuf.WriteString("CREATE TABLE IF NOT EXISTS tech_stack (target_id TEXT, cpe_uri TEXT, confidence REAL);\n")
	sqlBuf.WriteString("BEGIN TRANSACTION;\n")
	for _, t := range s.Targets {
		fmt.Fprintf(&sqlBuf, "INSERT OR REPLACE INTO targets VALUES (%q, %q, %q, %d);\n",
			t.TargetID, t.BaseURL, t.WAFVendor, t.Timestamp)
		for cpe, conf := range t.CPEs {
			fmt.Fprintf(&sqlBuf, "INSERT INTO tech_stack VALUES (%q, %q, %.3f);\n",
				t.TargetID, cpe, conf)
		}
	}
	sqlBuf.WriteString("COMMIT;\n")
	return os.WriteFile(filepath.Join(outDir, "kinetix_state.sqlite.sql"), sqlBuf.Bytes(), 0644)
}
