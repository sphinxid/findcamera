package onvif

// DeviceInfo holds information retrieved from an ONVIF device.
type DeviceInfo struct {
	// Connection
	IP              string `json:"ip"`
	Port            int    `json:"port"`
	ServiceURL      string `json:"service_url"`
	MediaServiceURL string `json:"media_service_url,omitempty"`
	DiscoveredBy    string `json:"discovered_by"` // "wsdiscovery" or "portscan"

	// GetDeviceInformation
	Manufacturer    string `json:"manufacturer,omitempty"`
	Model           string `json:"model,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	SerialNumber    string `json:"serial_number,omitempty"`
	HardwareID      string `json:"hardware_id,omitempty"`

	// Profiles and stream URIs
	Profiles []Profile `json:"profiles,omitempty"`

	// Error during probing (if any)
	ProbeError string `json:"probe_error,omitempty"`
}

// Profile represents an ONVIF media profile and its stream URI.
type Profile struct {
	Name      string `json:"name"`
	Token     string `json:"token"`
	StreamURI string `json:"stream_uri,omitempty"`
}
