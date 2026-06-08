# findcamera

A CLI tool that scans a local network for ONVIF-capable IP cameras and NVRs.

## Disclaimer

> **This tool is intended for educational and research purposes only.**
>
> Only use `findcamera` on networks and devices you own or have been explicitly authorised to test. Scanning, probing, or attempting to authenticate against devices without the owner's permission may violate local laws and regulations.
>
> The authors accept no responsibility for any misuse of this tool or any damage, legal consequences, or policy violations that may result from its use.

## Features

- **WS-Discovery** — sends a UDP multicast probe to `239.255.255.250:3702` to discover devices that announce themselves on the LAN.
- **TCP port scan** — connects to every host in the specified subnet(s) across all common ONVIF/camera ports.
- **Full ONVIF interrogation** — for every confirmed endpoint retrieves:
  - Manufacturer, model, firmware version, serial number, hardware ID
  - Media service URL (resolved from `GetCapabilities`)
  - All media profiles with RTSP stream URIs
  - Per-profile video codec, resolution, FPS, bitrate, H.264 profile
  - Per-profile audio codec and sample rate
- **Automatic credential fallback** — loads `default.csv` and tries each credential in order when a device requires authentication. Credentials that work for a given brand+model are cached and tried first on subsequent devices of the same type.
- **Deduplication** — devices found by both WS-Discovery and port scan appear as a single row with `Discovered By: wsdiscovery+portscan`.
- **Flexible output** — grouped device+stream table on screen; optional JSON and/or CSV export.
- **Configurable concurrency** — `--workers` flag (default 50).

## ONVIF ports scanned

`80`, `443`, `554`, `1935`, `2020`, `5000`, `7001`, `8000`, `8080`, `8081`, `8082`, `8083`, `8086`, `8090`, `8443`, `8554`, `9000`, `10000`, `10080`, `10554`, `11080`, `18080`, `34567`, `37777`, `49152`

## Installation

```bash
git clone https://github.com/sphinxid/findcamera
cd findcamera
go build -o findcamera .
```

Requires Go 1.21+. No CGO dependencies.

## Usage

```
findcamera [--subnet 192.168.1.0/24] [flags]

Flags:
  -s, --subnet stringArray   CIDR subnet(s) to scan, e.g. 192.168.1.0/24 (repeatable)
  -w, --workers int          concurrent scan workers (default 50)
  -t, --timeout int          TCP connect timeout per port in milliseconds (default 500)
  -o, --output string        output format: table | json | csv | all (default "table")
  -f, --file string          output file path without extension for json/csv/all (default "cameras")
  -c, --creds-file string    credential list CSV to try on protected devices (default "default.csv")
  -u, --username string      explicit ONVIF username — skips default.csv entirely
  -p, --password string      ONVIF password (used with --username)
      --discovery-timeout    seconds to wait for WS-Discovery responses (default 30)
      --no-discovery         skip WS-Discovery multicast probe
      --no-portscan          skip TCP port scan (WS-Discovery only)
  -v, --verbose              print verbose progress messages
  -h, --help                 help
```

## Examples

```bash
# Scan a single subnet, display results on screen
findcamera --subnet 192.168.1.0/24

# Scan multiple subnets, save as JSON
findcamera --subnet 192.168.1.0/24 --subnet 10.0.0.0/24 --output json --file cameras

# Save both JSON and CSV
findcamera --subnet 192.168.0.0/24 --output all --file scan

# Use a specific credential (skips default.csv)
findcamera --subnet 192.168.0.0/24 --username admin --password secret

# WS-Discovery only (no port scan), verbose
findcamera --no-portscan --verbose

# Port scan only, fast timeout, 200 workers
findcamera --subnet 10.0.1.0/24 --no-discovery --timeout 300 --workers 200

# Use a custom credential list
findcamera --subnet 192.168.1.0/24 --creds-file mycreds.csv
```

## Credential handling

When a device requires authentication, `findcamera` tries credentials automatically in this order:

1. **No credentials** — tried first on every device; open devices resolve instantly.
2. **Cached credential** (if applicable) — if the same brand+model was already successfully authenticated earlier in the scan, that credential is tried second.
3. **Full credential list** — all entries from `default.csv` (or `--creds-file`) are tried in order.

If `--username` is provided on the command line, `default.csv` is **not loaded** and only the explicit credential is tried (after no-auth).

### default.csv format

```csv
brand,username,password
Hikvision,admin,12345
Hikvision,admin,<NULL>
Dahua,admin,admin
```

- **Header row** (`brand,username,password`) is required and automatically skipped.
- **`<NULL>`** in the password column means an empty password (no password).
- Lines starting with `#` are treated as comments and ignored.
- Duplicate `username:password` pairs are deduplicated automatically.

The bundled `default.csv` includes common default credentials for Hikvision, Dahua, Axis, Meari, and generic cameras.

## Output

### Table (default)

Each device gets its own block with streams, codec, and encoding info directly below it — no cross-referencing required.

```
Found 2 device(s)
════════════════════════════════════════════════════════════════════════════════
[1] 192.168.5.131:8000  Meari Bullet 4S
    Firmware:       5.6.0
    Serial:         115332150
    Discovered by:  wsdiscovery
    Auth:           (none required)
    Service URL:    http://192.168.5.131:8000/onvif/device_service

    Profile      RTSP URI                                           Codec  Resolution  FPS  Bitrate    Audio
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────
    PROFILE_000  rtsp://192.168.5.131:8554/Streaming/Channels/101  H264   2560x1440   20   4096 kbps  -
    PROFILE_001  rtsp://192.168.5.131:8554/Streaming/Channels/102  H264   640x360     15   512 kbps   -
────────────────────────────────────────────────────────────────────────────────
[2] 192.168.5.204  Acme Cam1
    Firmware:       1.0
    Serial:         AAA
    Discovered by:  wsdiscovery+portscan
    Auth (username):  admin
    Service URL:    http://192.168.5.204/onvif/device_service
    Media URL:      http://192.168.5.204/onvif/media_service

    Profile      RTSP URI                         Codec      Resolution  FPS  Bitrate    Audio
    ──────────────────────────────────────────────────────────────────────────────────────────
    MainStream   rtsp://192.168.5.204:554/main    H264/High  1920x1080   25   2048 kbps  AAC 44100Hz
    SubStream    rtsp://192.168.5.204:554/sub     H264       640x360     15   512 kbps   G711 8000Hz
════════════════════════════════════════════════════════════════════════════════
```

### JSON (`--output json`)

One object per device. Profiles include full video/audio encoding details.

```json
[
  {
    "ip": "192.168.5.131",
    "port": 8000,
    "service_url": "http://192.168.5.131:8000/onvif/device_service",
    "media_service_url": "http://192.168.5.131:8000/onvif/media_service",
    "discovered_by": "wsdiscovery",
    "manufacturer": "Meari",
    "model": "Bullet 4S",
    "firmware_version": "5.6.0",
    "serial_number": "115332150",
    "profiles": [
      {
        "name": "PROFILE_000",
        "token": "T0",
        "stream_uri": "rtsp://192.168.5.131:8554/Streaming/Channels/101",
        "video_codec": "H264",
        "width": 2560,
        "height": 1440,
        "fps": 20,
        "bitrate_kbps": 4096
      }
    ]
  }
]
```

### CSV (`--output csv`)

One row per profile; devices with no profiles get a single row with empty profile fields.

Columns:
```
ip, port, service_url, media_service_url, discovered_by, auth_username,
manufacturer, model, firmware_version, serial_number, hardware_id,
profile_name, profile_token, stream_uri,
video_codec, h264_profile, width, height, fps, bitrate_kbps,
audio_codec, audio_sample_rate, audio_bitrate,
probe_error
```

## Project structure

```
findcamera/
├── main.go
├── default.csv                     # bundled default credential list
├── cmd/
│   └── root.go                     # Cobra CLI, orchestration, dedup, output dispatch
└── internal/
    ├── creds/
    │   └── creds.go                # CSV loader, credential cache (brand+model keyed)
    ├── onvif/
    │   ├── types.go                # DeviceInfo, Profile structs
    │   ├── probe.go                # SOAP client, GetCapabilities/DeviceInfo/Profiles/StreamUri
    │   └── tls.go                  # TLS config (self-signed cert tolerance)
    ├── output/
    │   └── output.go               # Table, JSON, CSV writers
    └── scanner/
        ├── subnet.go               # CIDR → host list
        ├── wsdiscovery.go          # UDP multicast WS-Discovery
        └── portscan.go             # Concurrent TCP port scanner
```

## Notes

- TLS certificate verification is skipped for HTTPS endpoints — cameras routinely use self-signed certificates.
- ONVIF authentication uses **WS-Security PasswordDigest** (SHA-1 nonce + timestamp).
- RTSP URIs returned by cameras may embed no credentials. Pass them separately to your player if needed:
  ```
  ffplay rtsp://admin:password@192.168.1.42:554/Streaming/Channels/101
  ```
- `/32` CIDR (single host) is supported.
- WS-Discovery may require running as root/sudo on some systems for UDP multicast socket binding.
