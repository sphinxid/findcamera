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

	"github.com/firman/findcamera/internal/onvif"
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
		pass := rec[2]
		if strings.EqualFold(strings.TrimSpace(pass), nullPassword) {
			pass = ""
		}
		entries = append(entries, Entry{
			Brand:    strings.TrimSpace(rec[0]),
			Username: strings.TrimSpace(rec[1]),
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
