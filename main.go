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
		log.Fatal("MOGNO_URL environment variable not set")

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
	log.Printf("Attempting to connect to database %s%s\n", u.Host, u.Path)
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
	log.Println("Successfully connected to database")

	log.Println("Starting drone API server")

	a := app.New()

	importRouter := mux.NewRouter()
	importRouter.HandleFunc("/api/projects/{pid}", handlers.UpdateProject(a)).Methods("PATCH")
	importRouter.HandleFunc("/api/projects/{pid}", handlers.ShowProject(a)).Methods("GET")
	importRouter.HandleFunc("/api/projects", handlers.IndexProject(a)).Methods("GET")

	negImport := negroni.New(
		negroni.NewLogger(),
		negroni.NewRecovery(),
	)
	negImport.Use(middleware.MongoMiddleware(s, dname))
	negImport.Use(middleware.AuthMiddleware(a))
	negImport.UseHandler(importRouter)

	router := mux.NewRouter()
	router.Handle("/api/projects/{pid}", negImport)
	router.Handle("/api/projects", negImport)
	server := negroni.New(
		negroni.NewLogger(),
		negroni.NewRecovery(),
	)
	server.UseHandler(router)

	log.Fatal(http.ListenAndServe(apiListener, server))
}
