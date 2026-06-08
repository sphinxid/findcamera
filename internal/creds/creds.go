// Package creds loads ONVIF credential lists from a CSV file.
// Expected CSV format (with header):
//
//	brand,username,password
//
// A password value of "<NULL>" (case-insensitive) is treated as an empty string.
// The no-auth case (empty username + empty password) is always prepended so
// unauthenticated devices are found first.
package creds

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/sphinxid/findcamera/internal/onvif"
)

const nullPassword = "<NULL>"

// Entry is one row from the credentials CSV.
type Entry struct {
	Brand    string
	Username string
	Password string
}

// LoadCSV reads a CSV file and returns the parsed credential entries.
// The header row (brand,username,password) is skipped automatically.
func LoadCSV(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open creds file %q: %w", path, err)
	}
	defer f.Close()
	return parseCSV(f)
}

func parseCSV(r io.Reader) ([]Entry, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.Comment = '#'

	var entries []Entry
	first := true
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse CSV: %w", err)
		}
		if len(rec) < 3 {
			continue
		}
		// Skip header
		if first {
			first = false
			if strings.EqualFold(rec[0], "brand") {
				continue
			}
		}
		user := strings.TrimSpace(rec[1])
		if strings.EqualFold(user, nullPassword) {
			user = ""
		}
		pass := strings.TrimSpace(rec[2])
		if strings.EqualFold(pass, nullPassword) {
			pass = ""
		}
		entries = append(entries, Entry{
			Brand:    strings.TrimSpace(rec[0]),
			Username: user,
			Password: pass,
		})
	}
	return entries, nil
}

// ToCredsList converts entries to the onvif.Credentials slice used for probing.
// A no-auth sentinel (empty username + password) is always placed first so
// open devices are matched without burning through the credential list.
func ToCredsList(entries []Entry) []onvif.Credentials {
	list := []onvif.Credentials{
		{Username: "", Password: ""}, // try unauthenticated first
	}
	seen := map[string]bool{"": true} // key = "user:pass"
	for _, e := range entries {
		key := e.Username + ":" + e.Password
		if seen[key] {
			continue
		}
		seen[key] = true
		list = append(list, onvif.Credentials{Username: e.Username, Password: e.Password})
	}
	return list
}

// ------------------------------------------------------------------
// Cache — thread-safe working-credential cache keyed by brand+model
// ------------------------------------------------------------------

// Cache stores the credential that successfully authenticated a given
// brand+model combination so future devices of the same type can try
// it first before falling back to the full list.
type Cache struct {
	mu    sync.RWMutex
	store map[string]onvif.Credentials // key = normalised "brand|model"
}

// NewCache returns an initialised Cache.
func NewCache() *Cache {
	return &Cache{store: make(map[string]onvif.Credentials)}
}

// cacheKey builds a normalised lookup key from brand and model.
// Both are lower-cased and trimmed; empty values become "*".
func cacheKey(brand, model string) string {
	b := strings.ToLower(strings.TrimSpace(brand))
	m := strings.ToLower(strings.TrimSpace(model))
	if b == "" {
		b = "*"
	}
	if m == "" {
		m = "*"
	}
	return b + "|" + m
}

// Put records a successful credential for a brand+model pair.
// A no-auth credential (empty username) is not cached — it adds no value.
func (c *Cache) Put(brand, model string, cr onvif.Credentials) {
	if cr.Username == "" {
		return
	}
	key := cacheKey(brand, model)
	c.mu.Lock()
	c.store[key] = cr
	c.mu.Unlock()
}

// Get returns the cached credential for brand+model and whether it exists.
func (c *Cache) Get(brand, model string) (onvif.Credentials, bool) {
	key := cacheKey(brand, model)
	c.mu.RLock()
	cr, ok := c.store[key]
	c.mu.RUnlock()
	return cr, ok
}

// Prioritise returns a credential list with the cached credential moved to
// the front (right after the no-auth sentinel), if one exists for brand+model.
// The rest of baseList follows without duplicating the cached entry.
func (c *Cache) Prioritise(brand, model string, baseList []onvif.Credentials) []onvif.Credentials {
	cached, ok := c.Get(brand, model)
	if !ok {
		return baseList
	}
	// Build: [no-auth, cached, ...rest without cached duplicate]
	result := make([]onvif.Credentials, 0, len(baseList)+1)
	for _, cr := range baseList {
		if cr.Username == "" {
			result = append(result, cr) // keep no-auth sentinel at front
			break
		}
	}
	result = append(result, cached)
	for _, cr := range baseList {
		if cr.Username == cached.Username && cr.Password == cached.Password {
			continue // already added
		}
		if cr.Username == "" {
			continue // already added
		}
		result = append(result, cr)
	}
	return result
}
