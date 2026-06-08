# findcamera

A CLI tool that scans a local network for ONVIF-capable IP cameras and NVRs.

## Features

- **WS-Discovery** — sends a UDP multicast probe (`239.255.255.250:3702`) to discover ONVIF devices that announce themselves.
- **TCP port scan** — scans every host in the specified subnet(s) across all common ONVIF ports.
- **Deep device interrogation** — for every confirmed ONVIF endpoint retrieves:
  - Manufacturer, model, firmware version, serial number
  - Media profiles and RTSP stream URIs
- **Flexible output** — display a table on screen, and optionally save results as **JSON** and/or **CSV**.
- **Configurable concurrency** — worker pool with `--workers` flag (default 100).

## ONVIF ports scanned

`80`, `443`, `554`, `1935`, `2020`, `5000`, `7001`, `8000`, `8080`, `8081`, `8082`, `8083`, `8086`, `8090`, `8443`, `8554`, `9000`, `10554`, `34567`, `37777`, `49152`

## Installation

```bash
git clone https://github.com/firman/findcamera
cd findcamera
go build -o findcamera .
```

## Usage

```
findcamera [--subnet 192.168.1.0/24] [flags]

Flags:
  -s, --subnet stringArray   CIDR subnet(s) to scan (repeatable)
  -w, --workers int          concurrent scan workers (default 100)
  -t, --timeout int          TCP connect timeout in ms (default 500)
  -o, --output string        output format: table | json | csv | all (default "table")
  -f, --file string          output file path without extension (default "cameras")
  -u, --username string      ONVIF username (optional)
  -p, --password string      ONVIF password (optional)
      --no-discovery         skip WS-Discovery multicast probe
      --no-portscan          skip TCP port scan
  -v, --verbose              print verbose progress messages
  -h, --help                 help
```

## Examples

```bash
# Scan a single subnet, print results as a table
findcamera --subnet 192.168.1.0/24

# Scan multiple subnets, save as JSON
findcamera --subnet 192.168.1.0/24 --subnet 10.0.0.0/24 --output json --file cameras

# Authenticated scan, save both JSON and CSV
findcamera --subnet 192.168.0.0/24 --username admin --password secret --output all --file scan

# WS-Discovery only (no port scan), verbose output
findcamera --no-portscan --verbose

# Port scan only, fast timeout, 200 workers
findcamera --subnet 10.0.1.0/24 --no-discovery --timeout 300 --workers 200
```

## Output

### Table (default)

```
#   IP             Port  Manufacturer  Model   Firmware  Serial        Profiles           Discovered By  Service URL
--------------------------------------------------------------------------------------------------------------------
1   192.168.1.42   80    Hikvision     DS-2CD  V5.6.3    0123456789AB  MainStream, Sub01  portscan       http://192.168.1.42/onvif/device_service

Stream URIs:
  [192.168.1.42] MainStream  ->  rtsp://192.168.1.42:554/Streaming/Channels/101
  [192.168.1.42] Sub01       ->  rtsp://192.168.1.42:554/Streaming/Channels/102
```

### JSON (`--output json`)

```json
[
  {
    "ip": "192.168.1.42",
    "port": 80,
    "service_url": "http://192.168.1.42/onvif/device_service",
    "discovered_by": "portscan",
    "manufacturer": "Hikvision",
    "model": "DS-2CD2183G0-I",
    "firmware_version": "V5.6.3",
    "serial_number": "0123456789AB",
    "profiles": [
      {
        "name": "MainStream",
        "token": "Profile_1",
        "stream_uri": "rtsp://192.168.1.42:554/Streaming/Channels/101"
      }
    ]
  }
]
```

### CSV (`--output csv`)

One row per profile. Columns:
`ip, port, service_url, discovered_by, manufacturer, model, firmware_version, serial_number, hardware_id, profile_name, profile_token, stream_uri, probe_error`

## Notes

- The tool skips certificate verification for HTTPS endpoints (cameras commonly use self-signed certs).
- ONVIF authentication (WS-Security PasswordDigest) is used when `--username` / `--password` are provided.
- `/32` subnets (single host) are supported.
- Run as root/sudo may be required on some systems for UDP multicast.
