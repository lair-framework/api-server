package app

import (
	"github.com/lair-framework/go-lair"
	"github.com/unrolled/render"
)

// App is used to map global variables used in handlers.
type App struct {
	R       *render.Render
	C       C
	Version string
	History int
}

// Response is used to return a status and message to handler requests.
type Response struct {
	Status  string
	Message string
}

// C is used to map collection names.
type C struct {
	AuthInterfaces string
	Credentials    string
	Files          string
	Hosts          string
	Issues         string
	Netblocks      string
	People         string
	Projects       string
	Services       string
	Versions       string
	WebDirectories string
}

// IsValidStatus returns true if the provided string is a valid lair status.
func (a *App) IsValidStatus(status string) bool {
	return status == lair.StatusGrey || status == lair.StatusBlue || status == lair.StatusGreen || status == lair.StatusOrange || status == lair.StatusRed
}

// New returns App with defaults.
func New() *App {
	a := &App{
		R: render.New(),
		C: C{
			AuthInterfaces: "auth_interfaces",
			Credentials:    "credentials",
			Files:          "files",
			Hosts:          "hosts",
			Issues:         "issues",
			Netblocks:      "netblocks",
			People:         "people",
			Projects:       "projects",
			Services:       "services",
			Versions:       "versions",
			WebDirectories: "web_directories",
		},
		Version: "2",
		History: 500,
	}
	return a
}
