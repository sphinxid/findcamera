package scanner

import (
	"fmt"
	"net"
	"time"
)

// OnvifPorts is the list of TCP ports commonly used by ONVIF / IP camera devices.
var OnvifPorts = []int{
	80,   // HTTP (most cameras)
	443,  // HTTPS
	554,  // RTSP
	1935, // RTMP
	2020, // Some Hikvision NVRs
	5000, // Some cameras
	7001, // Some cameras
	8000, // Hikvision default
	8080, // Dahua / generic
	8081,
	8082,
	8083,
	8086,
	8090,
	8443, // HTTPS alternate
	8554, // RTSP alternate
	9000, // Some cameras
	10554,
	34567, // Dahua DVR
	37777, // Dahua NVR
	49152, // UPnP / generic
}

const portScanTimeout = 500 * time.Millisecond

// OpenOnvifPorts returns the subset of OnvifPorts that are open (TCP connect)
// on the given host. Uses up to `workers` goroutines.
func OpenOnvifPorts(host string, workers int, timeout time.Duration) []int {
	if timeout <= 0 {
		timeout = portScanTimeout
	}
	if workers <= 0 {
		workers = 20
	}

	type result struct {
		port int
		open bool
	}

	portCh := make(chan int, len(OnvifPorts))
	resCh := make(chan result, len(OnvifPorts))

	for i := 0; i < workers; i++ {
		go func() {
			for port := range portCh {
				addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					conn.Close()
					resCh <- result{port: port, open: true}
				} else {
					resCh <- result{port: port, open: false}
				}
			}
		}()
	}

	for _, p := range OnvifPorts {
		portCh <- p
	}
	close(portCh)

	var open []int
	for range OnvifPorts {
		r := <-resCh
		if r.open {
			open = append(open, r.port)
		}
	}
	return open
}
