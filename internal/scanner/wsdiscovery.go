package scanner

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	wsDiscoveryMulticastAddr = "239.255.255.250:3702"
	wsDiscoveryTimeout       = 3 * time.Second

	wsDiscoveryProbe = `<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:findcamera-probe-001</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>`
)

var (
	// Extract XAddrs (service URLs) from WS-Discovery ProbeMatch responses
	xAddrsRe = regexp.MustCompile(`<[^>]*:?XAddrs[^>]*>([^<]+)<`)
	// Extract device types
	typesRe = regexp.MustCompile(`<[^>]*:?Types[^>]*>([^<]+)<`)
)

// WSDiscoveryResult holds a discovered device from WS-Discovery.
type WSDiscoveryResult struct {
	XAddrs []string
	Types  string
}

// WSDiscovery sends a WS-Discovery Probe to the multicast group and collects
// responses for the given duration. It returns discovered devices along with
// any error encountered sending the probe (responses may still have been
// collected before the error).
func WSDiscovery(timeout time.Duration) ([]WSDiscoveryResult, error) {
	if timeout <= 0 {
		timeout = wsDiscoveryTimeout
	}

	addr, err := net.ResolveUDPAddr("udp4", wsDiscoveryMulticastAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve multicast addr: %w", err)
	}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()

	_, err = conn.WriteTo([]byte(wsDiscoveryProbe), addr)
	if err != nil {
		return nil, fmt.Errorf("send WS-Discovery probe: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	seen := make(map[string]bool)
	var results []WSDiscoveryResult

	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			// Deadline exceeded or closed — stop collecting
			break
		}
		body := string(buf[:n])

		xm := xAddrsRe.FindStringSubmatch(body)
		if xm == nil {
			continue
		}
		rawAddrs := strings.Fields(strings.TrimSpace(xm[1]))
		if len(rawAddrs) == 0 {
			continue
		}

		key := strings.Join(rawAddrs, ",")
		if seen[key] {
			continue
		}
		seen[key] = true

		var types string
		if tm := typesRe.FindStringSubmatch(body); tm != nil {
			types = strings.TrimSpace(tm[1])
		}

		results = append(results, WSDiscoveryResult{
			XAddrs: rawAddrs,
			Types:  types,
		})
	}

	return results, nil
}
