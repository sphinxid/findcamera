package onvif

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	probeTimeout = 5 * time.Second
)

var httpClient = &http.Client{
	Timeout: probeTimeout,
	Transport: &http.Transport{
		TLSClientConfig:     insecureTLS(),
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 1,
	},
}

// ErrAuthRequired is returned by ProbeURL when the device demands credentials.
var ErrAuthRequired = fmt.Errorf("ONVIF authentication required")

// ProbeURLWithFallback tries each credential in the list in order.
// It first calls ProbeURL with the supplied cred; if the device returns an
// auth error it moves to the next entry. The first successful result is
// returned. If every credential fails with an auth error, ErrAuthRequired
// is returned. Other errors (network, not-ONVIF) abort immediately.
func ProbeURLWithFallback(serviceURL string, credsList []Credentials) (*DeviceInfo, error) {
	if len(credsList) == 0 {
		credsList = []Credentials{{}}
	}
	for _, c := range credsList {
		info, err := ProbeURL(serviceURL, c)
		if err == nil {
			info.AuthUsername = c.Username
			return info, nil
		}
		if isAuthError(err) {
			continue // try next credential
		}
		return nil, err // not an auth problem — surface the error
	}
	return nil, ErrAuthRequired
}

// ProbeURL attempts to identify and interrogate an ONVIF device at the given
// service URL. It returns a (possibly partial) DeviceInfo even when errors
// occur (ProbeError will be set).
func ProbeURL(serviceURL string, creds Credentials) (*DeviceInfo, error) {
	info := &DeviceInfo{ServiceURL: serviceURL}

	// Step 1: GetCapabilities to confirm it's an ONVIF device and get the
	// media service URL (may differ from the device service URL).
	mediaURL, err := getCapabilities(serviceURL, creds)
	if err != nil {
		return info, fmt.Errorf("GetCapabilities: %w", err)
	}
	// Fall back to the device service URL if no separate media XAddr was found.
	if mediaURL == "" {
		mediaURL = serviceURL
	}
	info.MediaServiceURL = mediaURL

	// Step 2: GetDeviceInformation
	if err := fillDeviceInfo(serviceURL, creds, info); err != nil {
		info.ProbeError = fmt.Sprintf("GetDeviceInformation: %v", err)
	}

	// Step 3: GetProfiles + GetStreamUri (sent to the media service URL)
	if err := fillProfiles(mediaURL, creds, info); err != nil {
		if info.ProbeError != "" {
			info.ProbeError += "; "
		}
		info.ProbeError += fmt.Sprintf("GetProfiles: %v", err)
	}

	return info, nil
}

// Credentials for ONVIF authentication (optional; empty = no auth).
type Credentials struct {
	Username string
	Password string
}

// ------------------------------------------------------------------
// SOAP helpers
// ------------------------------------------------------------------

func soapEnvelope(body string, creds Credentials) string {
	header := ""
	if creds.Username != "" {
		header = wssecHeader(creds.Username, creds.Password)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>%s</s:Header>
  <s:Body>%s</s:Body>
</s:Envelope>`, header, body)
}

func wssecHeader(username, password string) string {
	nonce := make([]byte, 16)
	rand.Read(nonce) //nolint:gosec
	nonce64 := base64.StdEncoding.EncodeToString(nonce)

	created := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	h := sha1.New()
	h.Write(nonce)
	h.Write([]byte(created))
	h.Write([]byte(password))
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf(`<wsse:Security>
    <wsse:UsernameToken>
      <wsse:Username>%s</wsse:Username>
      <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%s</wsse:Password>
      <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%s</wsse:Nonce>
      <wsu:Created>%s</wsu:Created>
    </wsse:UsernameToken>
  </wsse:Security>`, username, digest, nonce64, created)
}

// errHTTPAuth is a sentinel wrapping an HTTP 401/403 status.
type errHTTPAuth struct{ code int }

func (e errHTTPAuth) Error() string { return fmt.Sprintf("HTTP %d Unauthorized", e.code) }

func soapPost(url, action, body string, creds Credentials) (string, error) {
	env := soapEnvelope(body, creds)

	do := func(contentType, soapActionHeader string) (string, error) {
		req, err := http.NewRequest("POST", url, bytes.NewBufferString(env))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", contentType)
		if soapActionHeader != "" {
			req.Header.Set("SOAPAction", soapActionHeader)
		}
		req.Header.Set("User-Agent", "findcamera/1.0")

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		// Treat 401/403 as explicit auth errors
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return "", errHTTPAuth{resp.StatusCode}
		}
		return string(data), nil
	}

	// Try SOAP 1.2 first
	result, err := do(`application/soap+xml; charset=utf-8; action="`+action+`"`, "")
	if err != nil {
		// On connection/protocol error (not auth), retry with SOAP 1.1
		if _, isAuth := err.(errHTTPAuth); !isAuth {
			result, err = do("text/xml; charset=utf-8", `"`+action+`"`)
		}
	}
	return result, err
}

// isAuthError returns true if err represents an ONVIF authentication failure
// (HTTP 401/403 or a SOAP NotAuthorized / wsse:FailedAuthentication fault).
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(errHTTPAuth); ok {
		return true
	}
	msg := strings.ToLower(err.Error())
	authKeywords := []string{
		"notauthorized", "not authorized",
		"failedauthentication", "failed authentication",
		"sender not authorized", "authorization",
		"access denied",
	}
	for _, kw := range authKeywords {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------
// GetCapabilities
// ------------------------------------------------------------------

var mediaXAddrRe = regexp.MustCompile(`(?i)<[^>]*:?Media[^>]*>\s*<[^>]*:?XAddr[^>]*>([^<]+)<`)

// getCapabilities confirms the device is ONVIF and returns the media service
// XAddr (may be empty if not found in the response).
func getCapabilities(serviceURL string, creds Credentials) (mediaURL string, err error) {
	body := `<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>`
	resp, err := soapPost(serviceURL,
		"http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
		body, creds)
	if err != nil {
		return "", err
	}
	// SOAP fault auth errors come back as HTTP 200 with a Fault body
	if isSoapAuthFault(resp) {
		return "", errHTTPAuth{200}
	}
	if !strings.Contains(resp, "Capabilities") {
		return "", fmt.Errorf("unexpected response (not ONVIF?): %q", truncate(resp, 200))
	}
	if m := mediaXAddrRe.FindStringSubmatch(resp); m != nil {
		mediaURL = strings.TrimSpace(m[1])
	}
	return mediaURL, nil
}

// ------------------------------------------------------------------
// GetDeviceInformation
// ------------------------------------------------------------------

var (
	mfgRe      = xmlTagRe("Manufacturer")
	modelRe    = xmlTagRe("Model")
	fwRe       = xmlTagRe("FirmwareVersion")
	serialRe   = xmlTagRe("SerialNumber")
	hwIDRe     = xmlTagRe("HardwareId")
)

func xmlTagRe(tag string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)<[^>]*:?` + tag + `[^>]*>([^<]*)<`)
}

func fillDeviceInfo(serviceURL string, creds Credentials, info *DeviceInfo) error {
	body := `<tds:GetDeviceInformation/>`
	resp, err := soapPost(serviceURL,
		"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
		body, creds)
	if err != nil {
		return err
	}
	info.Manufacturer = xmlFirst(mfgRe, resp)
	info.Model = xmlFirst(modelRe, resp)
	info.FirmwareVersion = xmlFirst(fwRe, resp)
	info.SerialNumber = xmlFirst(serialRe, resp)
	info.HardwareID = xmlFirst(hwIDRe, resp)
	return nil
}

// ------------------------------------------------------------------
// GetProfiles + GetStreamUri
// ------------------------------------------------------------------

var (
	profileBlockRe = regexp.MustCompile(`(?is)<[^>]*:?Profiles[^>]+token="([^"]+)"[^>]*>(.*?)</[^>]*:?Profiles>`)
	profileNameRe  = xmlTagRe("Name")

	// VideoEncoderConfiguration block within a profile
	vecBlockRe     = regexp.MustCompile(`(?is)<[^>]*:?VideoEncoderConfiguration[^>]*>(.*?)</[^>]*:?VideoEncoderConfiguration>`)
	vecEncodingRe  = xmlTagRe("Encoding")
	vecWidthRe     = xmlTagRe("Width")
	vecHeightRe    = xmlTagRe("Height")
	vecFpsRe       = regexp.MustCompile(`(?i)<[^>]*:?(?:FrameRateLimit|FrameRate)[^>]*>(\d+)<`)
	vecBitrateRe   = regexp.MustCompile(`(?i)<[^>]*:?(?:BitrateLimit|Bitrate)[^>]*>(\d+)<`)
	vecH264ProfRe  = xmlTagRe("H264Profile")

	// AudioEncoderConfiguration block within a profile
	aecBlockRe       = regexp.MustCompile(`(?is)<[^>]*:?AudioEncoderConfiguration[^>]*>(.*?)</[^>]*:?AudioEncoderConfiguration>`)
	aecEncodingRe    = xmlTagRe("Encoding")
	aecSampleRateRe  = xmlTagRe("SampleRate")
	aecBitrateRe     = xmlTagRe("Bitrate")

	// Match <Uri> inside a <MediaUri> or <StreamUri> parent, or a bare <Uri> tag.
	streamURIRe = regexp.MustCompile(`(?i)<[^>]*:?(?:MediaUri|StreamUri|GetStreamUriResponse)[^>]*>[\s\S]*?<[^>]*:?Uri[^>]*>(rtsp://[^<]+)<`)
	// Fallback: any <Uri> containing rtsp://
	streamURIFallbackRe = regexp.MustCompile(`(?i)<[^>]*:?Uri[^>]*>(rtsp://[^<]+)<`)
)

func fillProfiles(serviceURL string, creds Credentials, info *DeviceInfo) error {
	body := `<trt:GetProfiles/>`
	resp, err := soapPost(serviceURL,
		"http://www.onvif.org/ver10/media/wsdl/GetProfiles",
		body, creds)
	if err != nil {
		return err
	}

	matches := profileBlockRe.FindAllStringSubmatch(resp, -1)
	for _, m := range matches {
		token := m[1]
		block := m[2]
		name := xmlFirst(profileNameRe, block)
		if name == "" {
			name = token
		}
		p := Profile{Name: name, Token: token}

		// Video encoder config
		if vm := vecBlockRe.FindStringSubmatch(block); vm != nil {
			vb := vm[1]
			p.VideoCodec = strings.ToUpper(xmlFirst(vecEncodingRe, vb))
			p.Width = xmlInt(vecWidthRe, vb)
			p.Height = xmlInt(vecHeightRe, vb)
			p.FrameRateFPS = xmlIntRe(vecFpsRe, vb)
			p.BitRateKbps = xmlIntRe(vecBitrateRe, vb)
			p.H264Profile = xmlFirst(vecH264ProfRe, vb)
		}

		// Audio encoder config
		if am := aecBlockRe.FindStringSubmatch(block); am != nil {
			ab := am[1]
			p.AudioCodec = strings.ToUpper(xmlFirst(aecEncodingRe, ab))
			p.AudioSampleRate = xmlInt(aecSampleRateRe, ab)
			p.AudioBitRate = xmlInt(aecBitrateRe, ab)
		}

		p.StreamURI = getStreamURI(serviceURL, creds, token)
		info.Profiles = append(info.Profiles, p)
	}
	return nil
}

func getStreamURI(serviceURL string, creds Credentials, token string) string {
	body := fmt.Sprintf(`<trt:GetStreamUri>
    <trt:StreamSetup>
      <tt:Stream>RTP-Unicast</tt:Stream>
      <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>
    </trt:StreamSetup>
    <trt:ProfileToken>%s</trt:ProfileToken>
  </trt:GetStreamUri>`, token)

	resp, err := soapPost(serviceURL,
		"http://www.onvif.org/ver10/media/wsdl/GetStreamUri",
		body, creds)
	if err != nil {
		return ""
	}
	// Try precise match first (Uri inside MediaUri/StreamUri block)
	if uri := xmlFirst(streamURIRe, resp); uri != "" {
		return strings.TrimSpace(uri)
	}
	// Fall back to any rtsp:// URI in the response
	if uri := xmlFirst(streamURIFallbackRe, resp); uri != "" {
		return strings.TrimSpace(uri)
	}
	return ""
}

// ------------------------------------------------------------------
// Utilities
// ------------------------------------------------------------------

func xmlFirst(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// xmlInt extracts the first integer value matched by re (expects capture group 1).
func xmlInt(re *regexp.Regexp, s string) int {
	v := xmlFirst(re, s)
	if v == "" {
		return 0
	}
	var n int
	fmt.Sscanf(v, "%d", &n)
	return n
}

// xmlIntRe is like xmlInt but the regex already has a \d+ capture group.
func xmlIntRe(re *regexp.Regexp, s string) int {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	var n int
	fmt.Sscanf(m[1], "%d", &n)
	return n
}

// isSoapAuthFault detects SOAP 200 responses that carry an authentication fault.
func isSoapAuthFault(body string) bool {
	lower := strings.ToLower(body)
	authFaultTokens := []string{
		"notauthorized",
		"failedauthentication",
		"sender not authorized",
		"wsse:failedauthentication",
		"ter:notauthorized",
	}
	hasFault := strings.Contains(lower, "fault")
	for _, tok := range authFaultTokens {
		if strings.Contains(lower, tok) && hasFault {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
