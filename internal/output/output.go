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

const divider = "════════════════════════════════════════════════════════════════════════════════"
const thinLine = "────────────────────────────────────────────────────────────────────────────────"

// PrintTable renders each device with its stream details grouped together.
func PrintTable(devices []*onvif.DeviceInfo) {
	if len(devices) == 0 {
		fmt.Println("No ONVIF devices found.")
		return
	}

	fmt.Printf("Found %d device(s)\n", len(devices))
	fmt.Println(divider)

	for i, d := range devices {
		// ── Device header ──────────────────────────────────────────
		fmt.Printf("[%d] %s", i+1, d.IP)
		if d.Port != 80 && d.Port != 443 {
			fmt.Printf(":%d", d.Port)
		}
		if d.Manufacturer != "" || d.Model != "" {
			fmt.Printf("  %s %s", d.Manufacturer, d.Model)
		}
		fmt.Println()

		// Device detail table (key: value pairs)
		dw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if d.FirmwareVersion != "" {
			fmt.Fprintf(dw, "    Firmware:\t%s\n", d.FirmwareVersion)
		}
		if d.SerialNumber != "" {
			fmt.Fprintf(dw, "    Serial:\t%s\n", d.SerialNumber)
		}
		fmt.Fprintf(dw, "    Discovered by:\t%s\n", d.DiscoveredBy)
		fmt.Fprintf(dw, "    Service URL:\t%s\n", d.ServiceURL)
		if d.MediaServiceURL != "" && d.MediaServiceURL != d.ServiceURL {
			fmt.Fprintf(dw, "    Media URL:\t%s\n", d.MediaServiceURL)
		}
		dw.Flush()

		// ── Profiles / streams ─────────────────────────────────────
		if len(d.Profiles) == 0 {
			fmt.Println("    (no profiles retrieved)")
		} else {
			fmt.Println()
			pw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(pw, "    Profile\tRTSP URI\tCodec\tResolution\tFPS\tBitrate\tAudio")
			fmt.Fprintln(pw, "    "+strings.Repeat("-", 90))
			for _, p := range d.Profiles {
				uri := p.StreamURI
				if uri == "" {
					uri = "(not available)"
				}
				res := ""
				if p.Width > 0 && p.Height > 0 {
					res = fmt.Sprintf("%dx%d", p.Width, p.Height)
				}
				fps := ""
				if p.FrameRateFPS > 0 {
					fps = fmt.Sprintf("%d", p.FrameRateFPS)
				}
				bitrate := ""
				if p.BitRateKbps > 0 {
					bitrate = fmt.Sprintf("%d kbps", p.BitRateKbps)
				}
				codec := p.VideoCodec
				if p.H264Profile != "" {
					codec += "/" + p.H264Profile
				}
				audio := p.AudioCodec
				if p.AudioSampleRate > 0 {
					audio += fmt.Sprintf(" %dHz", p.AudioSampleRate)
				}
				if audio == "" {
					audio = "-"
				}
				fmt.Fprintf(pw, "    %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					p.Name, uri, codec, res, fps, bitrate, audio)
			}
			pw.Flush()
		}

		if d.ProbeError != "" {
			fmt.Printf("    [warn] %s\n", d.ProbeError)
		}

		if i < len(devices)-1 {
			fmt.Println(thinLine)
		}
	}
	fmt.Println(divider)
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
		"ip", "port", "service_url", "media_service_url", "discovered_by",
		"manufacturer", "model", "firmware_version", "serial_number", "hardware_id",
		"profile_name", "profile_token", "stream_uri",
		"video_codec", "h264_profile", "width", "height", "fps", "bitrate_kbps",
		"audio_codec", "audio_sample_rate", "audio_bitrate",
		"probe_error",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, d := range devices {
		if len(d.Profiles) == 0 {
			row := deviceBaseRow(d)
			// pad all profile + encoding fields with empty strings
			row = append(row, "", "", "", "", "", "", "", "", "", "", "", "", d.ProbeError)
			if err := cw.Write(row); err != nil {
				return err
			}
			continue
		}
		for _, p := range d.Profiles {
			row := deviceBaseRow(d)
			row = append(row,
				p.Name, p.Token, p.StreamURI,
				p.VideoCodec, p.H264Profile,
				intOrEmpty(p.Width), intOrEmpty(p.Height),
				intOrEmpty(p.FrameRateFPS), intOrEmpty(p.BitRateKbps),
				p.AudioCodec,
				intOrEmpty(p.AudioSampleRate), intOrEmpty(p.AudioBitRate),
				d.ProbeError,
			)
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
		d.MediaServiceURL,
		d.DiscoveredBy,
		d.Manufacturer,
		d.Model,
		d.FirmwareVersion,
		d.SerialNumber,
		d.HardwareID,
	}
}

func intOrEmpty(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d", n)
}
