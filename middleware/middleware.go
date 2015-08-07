package middleware

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/context"
	"github.com/lair-framework/api-server/app"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// Mongo maps a copy of the session to the request context.
func Mongo(s *mgo.Session, dname string) negroni.HandlerFunc {
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
func Auth(server *app.App) negroni.HandlerFunc {
	return negroni.HandlerFunc(func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		db, ok := context.Get(req, "db").(*mgo.Database)
		if !ok {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Internal server error"})
			return
		}
		a := req.Header.Get("Authorization")
		if a == "" {
			server.R.JSON(w, http.StatusUnauthorized, &app.Response{Status: "Error", Message: "Not Authorized"})
			return
		}
		data, err := base64.StdEncoding.DecodeString(strings.Replace(a, "Basic ", "", 1))
		if err != nil {
			server.R.JSON(w, http.StatusUnauthorized, &app.Response{Status: "Error", Message: "Not Authorized"})
			return
		}
		user := &User{}
		parts := strings.Split(string(data), ":")
		if len(parts) < 2 {
			server.R.JSON(w, http.StatusUnauthorized, &app.Response{Status: "Error", Message: "Not Authorized"})
			return
		}
		if parts[0] == parts[1] {
			shaHash := sha256.New()
			if _, err := shaHash.Write([]byte(parts[0])); err != nil {
				server.R.JSON(w, http.StatusUnauthorized, &app.Response{Status: "Error", Message: "Not Authorized"})
				return
			}
			token := base64.StdEncoding.EncodeToString(shaHash.Sum(nil))
			if err := db.C("users").Find(bson.M{
				"services.resume.loginTokens": bson.M{"$elemMatch": bson.M{"hashedToken": token}},
			}).One(&user); err != nil {
				server.R.JSON(w, http.StatusUnauthorized, &app.Response{Status: "Error", Message: "Not Authorized"})
				return
			}
		} else {
			in := []bson.M{bson.M{"address": parts[0], "verified": false}}
			if err := db.C("users").Find(bson.M{"emails": bson.M{"$in": in}}).One(&user); err != nil {
				server.R.JSON(w, http.StatusUnauthorized, &app.Response{Status: "Error", Message: "Not Authorized"})
				return
			}
			shaHash := sha256.New()
			if _, err := shaHash.Write([]byte(parts[1])); err != nil {
				http.Error(w, "Not Authorized", http.StatusUnauthorized)
				return
			}
			h := hex.EncodeToString(shaHash.Sum(nil))
			if err := bcrypt.CompareHashAndPassword([]byte(user.Services.Password.Bcrypt), []byte(h)); err != nil {
				server.R.JSON(w, http.StatusUnauthorized, &app.Response{Status: "Error", Message: "Not Authorized"})
				return
			}
		}
		context.Set(req, "user", user)
		next(w, req)
	})
}

// User is a user from meteor.js.
type User struct {
	ID       string `bson:"_id"`
	Services struct {
		Password struct {
			Bcrypt string `bson:"bcrypt"`
		} `bson:"password"`
		Resume struct {
			Logintokens []struct {
				Hashedtoken string `bson:"hashedToken"`
			} `bson:"loginTokens"`
		} `bson:"resume"`
	} `bson:"services"`
	Emails []struct {
		Address string `bson:"address"`
	} `bson:"emails"`
}
