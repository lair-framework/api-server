package handlers

import (
	"net/http"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/lair-framework/api-server/app"
	"github.com/lair-framework/api-server/middleware"
	"github.com/lair-framework/go-lair"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// IndexHost is an HTTP handler to retrieve a list hosts for a given project.
func IndexHost(server *app.App) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		db := context.Get(req, "db").(*mgo.Database)
		if db == nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to access database"})
			return
		}

		user := context.Get(req, "user").(*middleware.User)
		if user == nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to retrieve user"})
			return
		}

		vars := mux.Vars(req)
		pid, ok := vars["pid"]
		if !ok {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Missing of invalid project id"})
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

		if count, err := db.C(server.C.Projects).Find(and).Count(); err != nil || count != 1 {
			server.R.JSON(w, http.StatusUnauthorized, &app.Response{Status: "Error", Message: "Not Authorized"})
			return
		}

		// Apply any url parameters as query filters
		m := bson.M{"projectId": pid}
		if req.FormValue("hostname") != "" {
			m["hostnames"] = req.FormValue("hostname")
		}

		hosts := []lair.Host{}
		if err := db.C(server.C.Hosts).Find(m).All(&hosts); err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to retrieve host index"})
			return
		}
		server.R.JSON(w, http.StatusOK, hosts)
	}
}
