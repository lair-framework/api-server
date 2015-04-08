package main

import (
	"net"
	"strconv"
	"strings"

	"github.com/lair-framework/go-lair"
	"github.com/unrolled/render"
)

const (
	ProjectsColl        = "projects"
	VersionsColl        = "versions"
	HostsColl           = "hosts"
	PortsColl           = "ports"
	VulnerabilitiesColl = "vulnerabilities"
)

// Used by API endpoints for rendering responses in JSON format
var R = render.New()

// Generic struct for defining errors
type DroneResponse struct {
	Status  string
	Message string
}

func IsValidStatus(status string) bool {
	return status == lair.StatusGrey || status == lair.StatusBlue || status == lair.StatusGreen || status == lair.StatusOrange || status == lair.StatusRed
}

// Convert IP address to integer
func IpToInt(ip net.IP) uint64 {
	bits := strings.Split(ip.String(), ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum uint64
	sum += uint64(b0) << 24
	sum += uint64(b1) << 16
	sum += uint64(b2) << 8
	sum += uint64(b3)

	return sum
}

// Convert integer to IP address
func IntToIp(ip uint64) net.IP {
	var bytes [4]byte
	bytes[0] = byte(ip & 0xFF)
	bytes[1] = byte((ip >> 8) & 0xFF)
	bytes[2] = byte((ip >> 16) & 0xFF)
	bytes[3] = byte((ip >> 24) & 0xFF)
	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
}
