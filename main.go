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
	keyPath := os.Getenv("KEY_PATH")
	if keyPath == "" {
		log.Fatal("KEY_PATH environment variable not set")
	}
	certPath := os.Getenv("CERT_PATH")
	if certPath == "" {
		log.Fatal("CERT_PATH environment variable not set")
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
	r := mux.NewRouter()
	r.HandleFunc("/api/export/{id}", Export).Methods("GET")
	r.HandleFunc("/api/import/{id}", Import).Methods("POST")
	server := negroni.New(
		negroni.NewLogger(),
		negroni.NewRecovery(),
	)
	server.Use(MongoMiddleware(s, dname))
	server.Use(AuthMiddleware())
	server.UseHandler(r)
	log.Fatal(http.ListenAndServeTLS(apiListener, certPath, keyPath, server))
}
