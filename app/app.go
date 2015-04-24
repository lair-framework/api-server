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
	Projects        string
	Versions        string
	Hosts           string
	Ports           string
	Vulnerabilities string
}

func (a *App) IsValidStatus(status string) bool {
	return status == lair.StatusGrey || status == lair.StatusBlue || status == lair.StatusGreen || status == lair.StatusOrange || status == lair.StatusRed
}

func New() *App {
	a := &App{
		R: render.New(),
		C: C{
			Projects:        "projects",
			Versions:        "versions",
			Hosts:           "hosts",
			Ports:           "ports",
			Vulnerabilities: "vulnerabilities",
		},
		Version: "0.1.0",
		History: 500,
	}
	return a
}
