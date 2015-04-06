package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// MongoMiddleware maps a copy of the session to the request context.
func MongoMiddleware(s *mgo.Session, dname string) negroni.HandlerFunc {
	return negroni.HandlerFunc(func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		session := s.Clone()
		defer session.Close()
		db := session.DB(dname)
		context.Set(req, "db", db)
		next(w, req)
	})
}

// Auth is a middleware to authenicate a user to Lair's meteor resources and
// ensures it has access the project provided in the url parameter.
func AuthMiddleware() negroni.HandlerFunc {
	return negroni.HandlerFunc(func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		db, ok := context.Get(req, "db").(*mgo.Database)
		if !ok {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		a := req.Header.Get("Authorization")
		if a == "" {
			http.Error(w, "Not Authorized", http.StatusUnauthorized)
			return
		}
		data, err := base64.StdEncoding.DecodeString(strings.Replace(a, "Basic ", "", 1))
		if err != nil {
			http.Error(w, "Not Authorized", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(string(data), ":")
		if len(parts) < 2 {
			http.Error(w, "Not Authorized", http.StatusUnauthorized)
			return
		}
		user := &User{}
		in := []bson.M{bson.M{"address": parts[0], "verified": false}}
		if err := db.C("users").Find(bson.M{"emails": bson.M{"$in": in}}).One(&user); err != nil {
			http.Error(w, "Not Authorized", http.StatusUnauthorized)
			return
		}
		shaHash := sha256.New()
		if _, err := shaHash.Write([]byte(parts[1])); err != nil {
			http.Error(w, "Not Authorized", http.StatusUnauthorized)
			return
		}
		h := hex.EncodeToString(shaHash.Sum(nil))
		if err := bcrypt.CompareHashAndPassword([]byte(user.Services.Password.Bcrypt), []byte(h)); err != nil {
			http.Error(w, "Not Authorized", http.StatusUnauthorized)
			return
		}
		vars := mux.Vars(req)
		pid := vars["pid"]
		q := bson.M{"_id": pid, "$or": []bson.M{bson.M{"owner": user.Id}, bson.M{"contributors": user.Id}}}
		if count, err := db.C("projects").Find(q).Count(); err != nil || count == 0 {
			http.Error(w, "Not Authorized", http.StatusForbidden)
			return
		}
		context.Set(req, "user", user)
		next(w, req)
	})
}

// User is a user from meteor.js.
type User struct {
	Id       string `bson:"_id"`
	Services struct {
		Password struct {
			Bcrypt string `bson:"bcrypt"`
		} `bson:"password"`
	} `bson:"services"`
	Emails []struct {
		Address string `bson:"address"`
	} `bson:"emails"`
}
