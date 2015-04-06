package main

import (
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
