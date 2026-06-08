package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/firman/findcamera/internal/onvif"
)

// PrintTable renders a summary table of discovered devices to stdout.
func PrintTable(devices []*onvif.DeviceInfo) {
	if len(devices) == 0 {
		fmt.Println("No ONVIF devices found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "#\tIP\tPort\tManufacturer\tModel\tFirmware\tSerial\tProfiles\tDiscovered By\tService URL")
	fmt.Fprintln(w, strings.Repeat("-", 120))

	for i, d := range devices {
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			i+1,
			d.IP,
			d.Port,
			d.Manufacturer,
			d.Model,
			d.FirmwareVersion,
			d.SerialNumber,
			profileSummary(d.Profiles),
			d.DiscoveredBy,
			d.ServiceURL,
		)
	}
	w.Flush()

	// Print stream URIs below the table for readability
	anyStreams := false
	for _, d := range devices {
		for _, p := range d.Profiles {
			if p.StreamURI != "" {
				if !anyStreams {
					fmt.Println("\nStream URIs:")
					anyStreams = true
				}
				fmt.Printf("  [%s] %s  ->  %s\n", d.IP, p.Name, p.StreamURI)
			}
		}
	}
}

// WriteJSON serialises devices as pretty JSON to the given file path.
func WriteJSON(path string, devices []*onvif.DeviceInfo) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create JSON file: %w", err)
	}
	defer f.Close()
	return encodeJSON(f, devices)
}

func encodeJSON(w io.Writer, devices []*onvif.DeviceInfo) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(devices)
}

// WriteCSV serialises devices as CSV to the given file path.
// One row per profile; devices with no profiles get a single row.
func WriteCSV(path string, devices []*onvif.DeviceInfo) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create CSV file: %w", err)
	}
	defer f.Close()
	return encodeCSV(f, devices)
}

func encodeCSV(w io.Writer, devices []*onvif.DeviceInfo) error {
	cw := csv.NewWriter(w)

	header := []string{
		"ip", "port", "service_url", "discovered_by",
		"manufacturer", "model", "firmware_version", "serial_number", "hardware_id",
		"profile_name", "profile_token", "stream_uri",
		"probe_error",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, d := range devices {
		if len(d.Profiles) == 0 {
			row := deviceBaseRow(d)
			row = append(row, "", "", "", d.ProbeError)
			if err := cw.Write(row); err != nil {
				return err
			}
			continue
		}
		for _, p := range d.Profiles {
			row := deviceBaseRow(d)
			row = append(row, p.Name, p.Token, p.StreamURI, d.ProbeError)
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}

	cw.Flush()
	return cw.Error()
}

func deviceBaseRow(d *onvif.DeviceInfo) []string {
	return []string{
		d.IP,
		fmt.Sprintf("%d", d.Port),
		d.ServiceURL,
		d.DiscoveredBy,
		d.Manufacturer,
		d.Model,
		d.FirmwareVersion,
		d.SerialNumber,
		d.HardwareID,
	}
}

func profileSummary(profiles []onvif.Profile) string {
	if len(profiles) == 0 {
		return "-"
	}
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = p.Name
	}
	return strings.Join(names, ", ")
}
