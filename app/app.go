package app

import (
	"github.com/lair-framework/go-lair"
	"github.com/unrolled/render"
)

type App struct {
	R       *render.Render
	C       C
	Version string
	History int
}

type Response struct {
	Status  string
	Message string
}

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

func (a *App) IsValidStatus(status string) bool {
	return status == lair.StatusGrey || status == lair.StatusBlue || status == lair.StatusGreen || status == lair.StatusOrange || status == lair.StatusRed
}

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
