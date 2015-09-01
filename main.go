package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/lair-framework/api-server/app"
	"github.com/lair-framework/api-server/handlers"
	"github.com/lair-framework/api-server/middleware"
	"gopkg.in/mgo.v2"
)

// TLSDial sets up a TLS connection to MongoDb.
func TLSDial(addr net.Addr) (net.Conn, error) {
	return tls.Dial(addr.Network(), addr.String(), &tls.Config{InsecureSkipVerify: true})
}
func main() {
	murl := os.Getenv("MONGO_URL")
	if murl == "" {
		log.Fatal("MONGO_URL environment variable not set")

	}
	apiListener := os.Getenv("API_LISTENER")
	if apiListener == "" {
		log.Fatal("API_LISTENER environment variable not set")
	}

	u, err := url.Parse(murl)
	if err != nil {
		log.Fatal("Erorr parsing MONGO_URL", err.Error())
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		log.Fatal("Error parsing query parameters", err.Error())
	}
	dname := u.Path[1:]
	s := &mgo.Session{}
	if opt, ok := q["ssl"]; ok && opt[0] == "true" {
		var user, pass string
		if u.User != nil {
			user = u.User.Username()
			p, set := u.User.Password()
			if set {
				pass = p
			}
		}
		d := &mgo.DialInfo{
			Addrs:    []string{u.Host},
			Direct:   true,
			Database: dname,
			Username: user,
			Password: pass,
			Dial:     TLSDial,
			Timeout:  time.Duration(10) * time.Second,
		}
		s, err = mgo.DialWithInfo(d)
		if err != nil {
			log.Fatal("Could not connect to database. Error: ", err.Error())
		}
	} else {
		s, err = mgo.Dial(murl)
		if err != nil {
			log.Fatal("Could not connect to database. Error: ", err.Error())
		}
	}

	a := app.New()
	db := s.DB(dname)
	defer s.Close()
	db.C(a.C.Hosts).EnsureIndexKey("projectId", "ipv4")
	db.C(a.C.Services).EnsureIndexKey("projectId", "hostId", "port", "protocol")
	db.C(a.C.Issues).EnsureIndexKey("projectId", "pluginIds")
	db.C(a.C.WebDirectories).EnsureIndexKey("projectId", "hostId", "path", "port")

	os.Mkdir(a.Filepath, 0600)
	r := mux.NewRouter()
	api := mux.NewRouter()
	api.HandleFunc("/api/projects/{pid}", handlers.UpdateProject(a)).Methods("PATCH")
	api.HandleFunc("/api/projects/{pid}", handlers.ShowProject(a)).Methods("GET")
	api.HandleFunc("/api/projects/{pid}/hosts", handlers.IndexHost(a)).Methods("GET")
	api.HandleFunc("/api/projects/{pid}/files", handlers.UploadFile(a)).Methods("POST")
	api.HandleFunc("/api/projects/{pid}/files/{filename:.*}", handlers.ServeFile(a)).Methods("GET")
	api.HandleFunc("/api/projects", handlers.IndexProject(a)).Methods("GET")
	r.PathPrefix("/api").Handler(negroni.New(
		negroni.HandlerFunc(middleware.Mongo(s, dname)),
		negroni.HandlerFunc(middleware.Auth(a)),
		negroni.Wrap(api),
	))
	rec := negroni.NewRecovery()
	rec.PrintStack = false
	n := negroni.New(
		negroni.NewLogger(),
		rec,
	)
	n.UseHandler(r)
	log.Printf("Listening on %s", apiListener)
	log.Fatal(http.ListenAndServe(apiListener, n))
}
