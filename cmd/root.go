package cmd

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/firman/findcamera/internal/creds"
	"github.com/firman/findcamera/internal/onvif"
	"github.com/firman/findcamera/internal/output"
	"github.com/firman/findcamera/internal/scanner"
	"github.com/spf13/cobra"
)

// CLI flags
var (
	flagSubnets    []string
	flagWorkers    int
	flagTimeout    int
	flagOutput     string // "table" (default), "json", "csv", "all"
	flagFile       string // output file path (without extension when "all")
	flagUsername   string
	flagPassword   string
	flagCredsFile  string // path to credentials CSV
	flagNoDiscover bool   // skip WS-Discovery
	flagNoPorts    bool   // skip port scan
	flagVerbose    bool
)

var rootCmd = &cobra.Command{
	Use:   "findcamera [--subnet 192.168.1.0/24] [flags]",
	Short: "Scan a local network for ONVIF-capable IP cameras and NVRs",
	Long: `findcamera discovers ONVIF devices on your network using two methods:

  1. WS-Discovery  — sends a UDP multicast probe (239.255.255.250:3702) to the
                     whole network, independent of any subnet argument.
  2. Port scan     — TCP-connects to every host in the specified subnet(s) on
                     all commonly used ONVIF ports.

For every discovered service URL the tool calls:
  GetCapabilities, GetDeviceInformation, GetProfiles, GetStreamUri

Results are displayed as a table by default, and can optionally be saved
as JSON and/or CSV.`,
	Example: `  # Scan a single subnet, display results on screen
  findcamera --subnet 192.168.1.0/24

  # Scan multiple subnets, save as JSON
  findcamera --subnet 192.168.1.0/24 --subnet 10.0.0.0/24 --output json --file cameras

  # Scan with credentials and save both JSON and CSV
  findcamera --subnet 192.168.0.0/24 --username admin --password secret --output all --file scan

  # WS-Discovery only (no port scan), verbose
  findcamera --no-portscan --verbose`,
	RunE: run,
}

// Execute is the entry point called from main.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringArrayVarP(&flagSubnets, "subnet", "s", nil,
		"CIDR subnet(s) to scan, e.g. 192.168.1.0/24 (repeatable)")
	rootCmd.Flags().IntVarP(&flagWorkers, "workers", "w", 100,
		"number of concurrent scan workers")
	rootCmd.Flags().IntVarP(&flagTimeout, "timeout", "t", 500,
		"TCP connect timeout per port in milliseconds")
	rootCmd.Flags().StringVarP(&flagOutput, "output", "o", "table",
		`output format: table | json | csv | all`)
	rootCmd.Flags().StringVarP(&flagFile, "file", "f", "cameras",
		"output file path (without extension) for json/csv/all formats")
	rootCmd.Flags().StringVarP(&flagUsername, "username", "u", "",
		"ONVIF username (overrides credential list)")
	rootCmd.Flags().StringVarP(&flagPassword, "password", "p", "",
		"ONVIF password (used together with --username)")
	rootCmd.Flags().StringVarP(&flagCredsFile, "creds-file", "c", "default.csv",
		"CSV file with default credentials to try (columns: brand,username,password; use <NULL> for empty password)")
	rootCmd.Flags().BoolVar(&flagNoDiscover, "no-discovery", false,
		"skip WS-Discovery multicast probe")
	rootCmd.Flags().BoolVar(&flagNoPorts, "no-portscan", false,
		"skip TCP port scan (only use WS-Discovery)")
	rootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false,
		"print verbose progress messages")
}

// ------------------------------------------------------------------

func run(_ *cobra.Command, _ []string) error {
	if flagNoPorts && flagNoDiscover {
		return fmt.Errorf("--no-discovery and --no-portscan cannot both be set")
	}
	if !flagNoPorts && len(flagSubnets) == 0 {
		fmt.Fprintln(os.Stderr, "Warning: no --subnet specified; only WS-Discovery will run.")
		flagNoDiscover = false
		flagNoPorts = true
	}

	// Build the base credential list.
	// If --username is given explicitly, ONLY use that credential (+ no-auth).
	// The default.csv is NOT loaded in this case.
	var credsList []onvif.Credentials
	if flagUsername != "" {
		logf("Using explicit credential: username=%q\n", flagUsername)
		credsList = []onvif.Credentials{
			{Username: "", Password: ""},
			{Username: flagUsername, Password: flagPassword},
		}
	} else {
		entries, err := creds.LoadCSV(flagCredsFile)
		if err != nil {
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: could not load creds file %q: %v\n", flagCredsFile, err)
			} else {
				logf("Creds file %q not found; will probe without authentication.\n", flagCredsFile)
			}
			entries = nil
		} else {
			logf("Loaded %d credential(s) from %s.\n", len(entries), flagCredsFile)
		}
		credsList = creds.ToCredsList(entries)
	}

	timeout := time.Duration(flagTimeout) * time.Millisecond

	// serviceURLs collected from both discovery methods; deduplicated.
	type urlSource struct {
		url          string
		ip           string
		port         int
		discoveredBy string
	}

	var mu sync.Mutex
	seen := make(map[string]bool)
	var pending []urlSource

	addURL := func(u urlSource) {
		mu.Lock()
		defer mu.Unlock()
		if !seen[u.url] {
			seen[u.url] = true
			pending = append(pending, u)
		}
	}

	// ── WS-Discovery ──────────────────────────────────────────────
	if !flagNoDiscover {
		logf("Running WS-Discovery (waiting 3s for responses)…\n")
		results, err := scanner.WSDiscovery(3 * time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WS-Discovery error: %v\n", err)
		}
		for _, r := range results {
			for _, xaddr := range r.XAddrs {
				ip, port := parseServiceURL(xaddr)
				addURL(urlSource{url: xaddr, ip: ip, port: port, discoveredBy: "wsdiscovery"})
				logf("  WS-Discovery: %s\n", xaddr)
			}
		}
		logf("WS-Discovery found %d device(s).\n", len(results))
	}

	// ── Port scan ─────────────────────────────────────────────────
	if !flagNoPorts {
		for _, cidr := range flagSubnets {
			hosts, err := scanner.HostsInCIDR(cidr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing subnet %q: %v\n", cidr, err)
				continue
			}
			logf("Scanning %d hosts in %s with %d workers…\n", len(hosts), cidr, flagWorkers)

			type portResult struct {
				host  string
				ports []int
			}

			hostCh := make(chan string, len(hosts))
			resCh := make(chan portResult, len(hosts))

			for i := 0; i < min(flagWorkers, len(hosts)); i++ {
				go func() {
					for h := range hostCh {
						open := scanner.OpenOnvifPorts(h, 20, timeout)
						resCh <- portResult{host: h, ports: open}
					}
				}()
			}

			for _, h := range hosts {
				hostCh <- h
			}
			close(hostCh)

			for range hosts {
				r := <-resCh
				for _, p := range r.ports {
					url := buildServiceURL(r.host, p)
					addURL(urlSource{url: url, ip: r.host, port: p, discoveredBy: "portscan"})
					logf("  Open port: %s:%d\n", r.host, p)
				}
			}
		}
	}

	if len(pending) == 0 {
		fmt.Println("No potential ONVIF endpoints found.")
		return nil
	}

	logf("\nProbing %d candidate endpoint(s)…\n\n", len(pending))

	// credCache holds the credential that worked for a given brand+model,
	// so devices of the same type discovered later try it first.
	credCache := creds.NewCache()

	// ── ONVIF probing ─────────────────────────────────────────────
	probeCh := make(chan urlSource, len(pending))
	devCh := make(chan *onvif.DeviceInfo, len(pending))

	probeWorkers := min(flagWorkers, len(pending))
	for i := 0; i < probeWorkers; i++ {
		go func() {
			for u := range probeCh {
				logf("  Probing %s …\n", u.url)

				// Step 1: try a quick unauthenticated GetDeviceInformation to
				// learn brand+model before committing to the full credential list.
				// This succeeds on open devices and on cameras that return device
				// info even without auth (common). On failure we skip to step 2.
				brand, model := quickGetBrandModel(u.url)

				// Step 2: build per-device credential list, promoting any cached
				// credential for this brand+model to the front.
				deviceCredsList := credCache.Prioritise(brand, model, credsList)
				if brand != "" && model != "" {
					if cached, ok := credCache.Get(brand, model); ok {
						logf("    Cache hit for %q %q → trying %q first\n", brand, model, cached.Username)
					}
				}

				info, err := onvif.ProbeURLWithFallback(u.url, deviceCredsList)
				if err != nil {
					if err == onvif.ErrAuthRequired {
						logf("    Auth required but no credential matched: %s\n", u.url)
					} else {
						logf("    Not ONVIF (or error): %v\n", err)
					}
					devCh <- nil
					continue
				}

				// Step 3: record the working credential in the cache.
				if info.AuthUsername != "" {
					logf("    Authenticated as %q\n", info.AuthUsername)
					credCache.Put(info.Manufacturer, info.Model,
						onvif.Credentials{Username: info.AuthUsername, Password: workingPassword(deviceCredsList, info.AuthUsername)})
				}

				info.IP = u.ip
				info.Port = u.port
				info.DiscoveredBy = u.discoveredBy
				devCh <- info
			}
		}()
	}

	for _, u := range pending {
		probeCh <- u
	}
	close(probeCh)

	var rawDevices []*onvif.DeviceInfo
	for range pending {
		if d := <-devCh; d != nil {
			rawDevices = append(rawDevices, d)
		}
	}

	// Dedup: same physical device may appear from both wsdiscovery and portscan.
	// Key by IP + SerialNumber (fall back to IP+Port when serial is absent).
	// Merge DiscoveredBy so the single row shows both sources when applicable.
	type dedupKey struct{ ip, serial string }
	seen2 := make(map[dedupKey]*onvif.DeviceInfo)
	var devices []*onvif.DeviceInfo
	for _, d := range rawDevices {
		serial := d.SerialNumber
		if serial == "" {
			serial = fmt.Sprintf("port%d", d.Port)
		}
		k := dedupKey{ip: d.IP, serial: serial}
		if existing, ok := seen2[k]; ok {
			// Merge discovery sources
			if existing.DiscoveredBy != d.DiscoveredBy &&
				!strings.Contains(existing.DiscoveredBy, d.DiscoveredBy) {
				existing.DiscoveredBy = existing.DiscoveredBy + "+" + d.DiscoveredBy
			}
			continue
		}
		seen2[k] = d
		devices = append(devices, d)
	}

	// Sort by IP then port for stable output
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].IP != devices[j].IP {
			return ipLess(devices[i].IP, devices[j].IP)
		}
		return devices[i].Port < devices[j].Port
	})

	// ── Output ────────────────────────────────────────────────────
	fmt.Println()
	switch strings.ToLower(flagOutput) {
	case "json":
		path := flagFile + ".json"
		if err := output.WriteJSON(path, devices); err != nil {
			return err
		}
		fmt.Printf("Results saved to %s\n", path)
		output.PrintTable(devices)

	case "csv":
		path := flagFile + ".csv"
		if err := output.WriteCSV(path, devices); err != nil {
			return err
		}
		fmt.Printf("Results saved to %s\n", path)
		output.PrintTable(devices)

	case "all":
		jsonPath := flagFile + ".json"
		csvPath := flagFile + ".csv"
		if err := output.WriteJSON(jsonPath, devices); err != nil {
			return err
		}
		if err := output.WriteCSV(csvPath, devices); err != nil {
			return err
		}
		fmt.Printf("Results saved to %s and %s\n", jsonPath, csvPath)
		output.PrintTable(devices)

	default: // "table"
		output.PrintTable(devices)
	}

	return nil
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

func logf(format string, args ...any) {
	if flagVerbose {
		fmt.Printf(format, args...)
	}
}

// quickGetBrandModel does a cheap unauthenticated probe to learn brand+model
// before committing to the credential list. Returns empty strings on any error.
func quickGetBrandModel(serviceURL string) (brand, model string) {
	return onvif.GetBrandModel(serviceURL)
}

// workingPassword finds the password for a given username in a credential list.
// Returns empty string if not found.
func workingPassword(list []onvif.Credentials, username string) string {
	for _, c := range list {
		if c.Username == username {
			return c.Password
		}
	}
	return ""
}

// buildServiceURL constructs the ONVIF device service URL for a host:port.
func buildServiceURL(host string, port int) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	// Standard ONVIF device service path
	if port == 80 || port == 443 {
		return fmt.Sprintf("%s://%s/onvif/device_service", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%d/onvif/device_service", scheme, host, port)
}

// parseServiceURL extracts IP and port from a service URL.
func parseServiceURL(rawURL string) (string, int) {
	// Strip scheme
	s := rawURL
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	// Strip path
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// No port in URL
		return s, 80
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

func ipLess(a, b string) bool {
	ia := net.ParseIP(a)
	ib := net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	ia4 := ia.To4()
	ib4 := ib.To4()
	if ia4 == nil || ib4 == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ia4[i] != ib4[i] {
			return ia4[i] < ib4[i]
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
