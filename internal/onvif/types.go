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

	// Video encoding details (from VideoEncoderConfiguration)
	VideoCodec   string `json:"video_codec,omitempty"`   // H264, H265, MPEG4, JPEG …
	Width        int    `json:"width,omitempty"`
	Height       int    `json:"height,omitempty"`
	FrameRateFPS int    `json:"fps,omitempty"`
	BitRateKbps  int    `json:"bitrate_kbps,omitempty"`
	H264Profile  string `json:"h264_profile,omitempty"`  // Baseline, Main, High, Extended

	// Audio encoding details (from AudioEncoderConfiguration)
	AudioCodec     string `json:"audio_codec,omitempty"`  // G711, G726, AAC …
	AudioSampleRate int   `json:"audio_sample_rate,omitempty"`
	AudioBitRate   int    `json:"audio_bitrate,omitempty"`
}
