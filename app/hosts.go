package app

import (
	"net/http"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/lair-framework/go-lair"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// IndexHost is an HTTP handler to retrieve a list hosts for a given project.
func (a *App) IndexHost(w http.ResponseWriter, req *http.Request) {
	db := context.Get(req, "db").(*mgo.Database)
	if db == nil {
		a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Unable to access database"})
		return
	}

	vars := mux.Vars(req)
	pid, ok := vars["pid"]
	if !ok {
		a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Missing of invalid project id"})
		return
	}

	// Apply any url parameters as query filters
	m := bson.M{"projectId": pid}
	if req.FormValue("hostname") != "" {
		m["hostnames"] = req.FormValue("hostname")
	}

	hosts := []lair.Host{}
	if err := db.C(a.C.Hosts).Find(m).All(&hosts); err != nil {
		a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Unable to retrieve host index"})
		return
	}
	a.R.JSON(w, http.StatusOK, hosts)
}
