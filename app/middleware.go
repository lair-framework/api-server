package app

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

// Mongo maps a copy of the session to the request context.
func (a *App) Mongo() negroni.HandlerFunc {
	return negroni.HandlerFunc(func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		session := a.S.Clone()
		defer session.Close()
		db := session.DB(a.DName)
		context.Set(req, "db", db)
		next(w, req)
	})
}

// AuthProject is a middleware to authorize a user to a project.
func (a *App) AuthProject() negroni.HandlerFunc {
	return negroni.HandlerFunc(func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		db, ok := context.Get(req, "db").(*mgo.Database)
		if !ok {
			a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Internal server error"})
			return
		}
		vars := mux.Vars(req)
		pid, ok := vars["pid"]
		if !ok {
			a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Missing of invalid project id"})
			return
		}

		user := context.Get(req, "user").(*User)
		if user == nil {
			a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Unable to retrieve user"})
			return
		}

		// Ensure query is restricted to only hosts to which the user is authorized
		and := &bson.M{
			"_id": pid,
			"$or": []bson.M{
				bson.M{"owner": user.ID},
				bson.M{"contributors": user.ID},
			},
		}

		if count, err := db.C(a.C.Projects).Find(and).Count(); err != nil || count != 1 {
			a.R.JSON(w, http.StatusForbidden, &Response{Status: "Error", Message: "Forbidden"})
			return
		}
		next(w, req)
	})
}

// Auth is a middleware to authenicate a user to Lair's meteor resources and
// ensures it has access the project provided in the url parameter.
func (a *App) Auth() negroni.HandlerFunc {
	return negroni.HandlerFunc(func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		db, ok := context.Get(req, "db").(*mgo.Database)
		if !ok {
			a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Internal server error"})
			return
		}
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			a.R.JSON(w, http.StatusUnauthorized, &Response{Status: "Error", Message: "Not Authorized"})
			return
		}
		data, err := base64.StdEncoding.DecodeString(strings.Replace(authHeader, "Basic ", "", 1))
		if err != nil {
			a.R.JSON(w, http.StatusUnauthorized, &Response{Status: "Error", Message: "Not Authorized"})
			return
		}
		user := &User{}
		parts := strings.Split(string(data), ":")
		if len(parts) < 2 {
			a.R.JSON(w, http.StatusUnauthorized, &Response{Status: "Error", Message: "Not Authorized"})
			return
		}
		if parts[0] == parts[1] {
			shaHash := sha256.New()
			if _, err := shaHash.Write([]byte(parts[0])); err != nil {
				a.R.JSON(w, http.StatusUnauthorized, &Response{Status: "Error", Message: "Not Authorized"})
				return
			}
			token := base64.StdEncoding.EncodeToString(shaHash.Sum(nil))
			if err := db.C("users").Find(bson.M{
				"services.resume.loginTokens": bson.M{"$elemMatch": bson.M{"hashedToken": token}},
			}).One(&user); err != nil {
				a.R.JSON(w, http.StatusUnauthorized, &Response{Status: "Error", Message: "Not Authorized"})
				return
			}
		} else {
			in := []bson.M{bson.M{"address": parts[0], "verified": false}}
			if err := db.C("users").Find(bson.M{"emails": bson.M{"$in": in}}).One(&user); err != nil {
				a.R.JSON(w, http.StatusUnauthorized, &Response{Status: "Error", Message: "Not Authorized"})
				return
			}
			shaHash := sha256.New()
			if _, err := shaHash.Write([]byte(parts[1])); err != nil {
				http.Error(w, "Not Authorized", http.StatusUnauthorized)
				return
			}
			h := hex.EncodeToString(shaHash.Sum(nil))
			if err := bcrypt.CompareHashAndPassword([]byte(user.Services.Password.Bcrypt), []byte(h)); err != nil {
				a.R.JSON(w, http.StatusUnauthorized, &Response{Status: "Error", Message: "Not Authorized"})
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
