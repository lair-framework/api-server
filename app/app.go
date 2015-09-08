package app

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/lair-framework/go-lair"
	"github.com/unrolled/render"
	"gopkg.in/mgo.v2"
)

// App is used to map global variables used in handlers.
type App struct {
	R        *render.Render
	C        C
	S        *mgo.Session
	Version  string
	History  int
	Filepath string
	DName    string
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

type O struct {
	S        *mgo.Session
	DName    string
	Filepath string
}

// IsValidStatus returns true if the provided string is a valid lair status.
func (a *App) IsValidStatus(status string) bool {
	return status == lair.StatusGrey || status == lair.StatusBlue || status == lair.StatusGreen || status == lair.StatusOrange || status == lair.StatusRed
}

// New returns App with defaults.
func New(o *O) *App {
	f, _ := os.Getwd()
	filepath := filepath.Join(f, "files")
	if o.Filepath != "" {
		filepath = o.Filepath
	}
	if o.DName == "" {
		o.DName = "lair"
	}
	a := &App{
		S:        o.S,
		DName:    o.DName,
		R:        render.New(),
		Filepath: filepath,
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

func (a *App) Router() *mux.Router {
	r := mux.NewRouter()
	r.Handle("/api/projects", a.newAuthHandler(a.IndexProject)).Methods("GET")
	r.Handle("/api/projects/{pid}", a.newProjectAuthHandler(a.UpdateProject)).Methods("PATCH")
	r.Handle("/api/projects/{pid}", a.newProjectAuthHandler(a.ShowProject)).Methods("GET")
	r.Handle("/api/projects/{pid}/hosts", a.newProjectAuthHandler(a.IndexHost)).Methods("GET")
	r.Handle("/api/projects/{pid}/files", a.newProjectAuthHandler(a.UploadFile)).Methods("POST")
	r.Handle("/api/projects/{pid}/files/{filename:.*}", a.newAnonHandler(a.ServeFile)).Methods("GET")
	r.Handle("/api/projects/{pid}/files/{filename:.*}", a.newProjectAuthHandler(a.RemoveFile)).Methods("DELETE")
	r.Handle("/api/projects/{pid}/hosts/{hid}/files/{filename:.*}", a.newProjectAuthHandler(a.RemoveFile)).Methods("DELETE")
	r.Handle("/api/projects/{pid}/services/{sid}/files/{filename:.*}", a.newProjectAuthHandler(a.RemoveFile)).Methods("DELETE")
	r.Handle("/api/projects/{pid}/issues/{iid}/files/{filename:.*}", a.newProjectAuthHandler(a.RemoveFile)).Methods("DELETE")
	return r
}

func (a *App) newAnonHandler(f func(w http.ResponseWriter, r *http.Request)) *negroni.Negroni {
	n := negroni.New()
	n.Use(a.Mongo())
	n.UseHandlerFunc(f)
	return n
}

func (a *App) newAuthHandler(f func(w http.ResponseWriter, r *http.Request)) *negroni.Negroni {
	n := negroni.New()
	n.Use(a.Mongo())
	n.Use(a.Auth())
	n.UseHandlerFunc(f)
	return n
}

func (a *App) newProjectAuthHandler(f func(w http.ResponseWriter, r *http.Request)) *negroni.Negroni {
	n := negroni.New()
	n.Use(a.Mongo())
	n.Use(a.Auth())
	n.Use(a.AuthProject())
	n.UseHandlerFunc(f)
	return n
}
