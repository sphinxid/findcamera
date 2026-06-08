package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
)

// HostsInCIDR returns all usable host IP addresses in the given CIDR block.
// The network address and broadcast address are excluded.
func HostsInCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	// Detect IP version
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDRs are supported, got %q", cidr)
	}

	mask := ipNet.Mask
	ones, bits := mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("unexpected mask bits %d", bits)
	}

	// Number of host bits
	hostBits := bits - ones
	numHosts := (1 << uint(hostBits))

	// For /32 just return the single host
	if hostBits == 0 {
		return []string{ip4.String()}, nil
	}

	networkInt := binary.BigEndian.Uint32([]byte(ipNet.IP.To4()))

	hosts := make([]string, 0, numHosts-2)
	for i := 1; i < numHosts-1; i++ {
		hostInt := networkInt + uint32(i)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, hostInt)
		hosts = append(hosts, net.IP(b).String())
	}
	return hosts, nil
}
