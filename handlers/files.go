package handlers

import (
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/lair-framework/api-server/app"
	"github.com/lair-framework/api-server/middleware"
	"github.com/lair-framework/go-lair"
	"github.com/mholt/binding"
	"github.com/nu7hatch/gouuid"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type fileRequest struct {
	File      *multipart.FileHeader
	hostID    string
	serviceID string
	issueID   string
}

func (f *fileRequest) FieldMap() binding.FieldMap {
	return binding.FieldMap{
		&f.File:      "file",
		&f.hostID:    "host_id",
		&f.serviceID: "service_id",
		&f.issueID:   "issue_id",
	}
}

func (f *fileRequest) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	if f.File == nil {
		errs = append(errs, binding.Error{
			FieldNames: []string{"file"},
			Message:    "file required",
		})
	}
	return errs
}

func ServeFile(server *app.App) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		db := context.Get(req, "db").(*mgo.Database)
		if db == nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to connect to database"})
			return
		}
		user := context.Get(req, "user").(*middleware.User)
		vars := mux.Vars(req)
		pid, ok := vars["pid"]
		if !ok {
			server.R.JSON(w, http.StatusBadRequest, &app.Response{Status: "Error", Message: "Missing project id"})
			return
		}
		q := bson.M{"_id": pid, "$or": []bson.M{bson.M{"owner": user.ID}, bson.M{"contributors": user.ID}}}
		if count, err := db.C("projects").Find(q).Count(); err != nil || count == 0 {
			server.R.JSON(w, http.StatusForbidden, &app.Response{Status: "Error", Message: "Forbidden"})
			return
		}

		filename, ok := vars["filename"]
		if !ok {
			server.R.JSON(w, http.StatusBadRequest, &app.Response{Status: "Error", Message: "Missing filename"})
			return
		}
		found := false
		projectQ := bson.M{"_id": pid, "files": bson.M{"$elemMatch": bson.M{"url": req.URL.Path}}}
		subQ := bson.M{"projectId": pid, "files": bson.M{"$elemMatch": bson.M{"url": req.URL.Path}}}
		if c, err := db.C(server.C.Projects).Find(projectQ).Count(); c != 0 && err == nil {
			found = true
		} else if c, err := db.C(server.C.Hosts).Find(subQ).Count(); c != 0 && err == nil {
			found = true
		} else if c, err := db.C(server.C.Services).Find(subQ).Count(); c != 0 && err == nil {
			found = true
		} else if c, err := db.C(server.C.Issues).Find(subQ).Count(); c != 0 && err == nil {
			found = true
		}

		if !found {
			server.R.JSON(w, http.StatusNotFound, &app.Response{Status: "Error", Message: "File not found"})
			return
		}
		http.ServeFile(w, req, path.Join(server.Filepath, path.Clean(filename)))
	}
}

func UploadFile(server *app.App) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		db := context.Get(req, "db").(*mgo.Database)
		if db == nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to connect to database"})
			return
		}
		user := context.Get(req, "user").(*middleware.User)
		vars := mux.Vars(req)
		pid, ok := vars["pid"]
		if ok {
			q := bson.M{"_id": pid, "$or": []bson.M{bson.M{"owner": user.ID}, bson.M{"contributors": user.ID}}}
			if count, err := db.C("projects").Find(q).Count(); err != nil || count == 0 {
				server.R.JSON(w, http.StatusForbidden, &app.Response{Status: "Error", Message: "Forbidden"})
				return
			}
		}
		// Max 30 MB.
		binding.MaxMemory = 30000000

		u := &fileRequest{}
		if errs := binding.Bind(req, u); errs.Handle(w) {
			return
		}
		fh, err := u.File.Open()
		if err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Internal server error"})
			log.Println(err)
			return
		}
		uid, err := uuid.NewV4()
		if err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Internal server error"})
			log.Println(err)
			return
		}
		uname := uid.String() + path.Ext(path.Base(u.File.Filename))
		fname := path.Join(server.Filepath, uname)
		hf, err := os.Create(fname)
		if err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Internal server error"})
			log.Println(err)
			return
		}
		if _, err := io.Copy(hf, fh); err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Internal server error"})
			log.Println(err)
			return
		}

		fileURL := req.URL.Path + "/" + uname
		lairFile := lair.File{
			FileName: u.File.Filename,
			URL:      fileURL,
		}

		if u.hostID != "" {
			if err := db.C(server.C.Hosts).Update(bson.M{"projectId": pid, "_id": u.hostID}, bson.M{"$addToSet": bson.M{"files": lairFile}}); err != nil {
				server.R.JSON(w, http.StatusNotFound, &app.Response{Status: "Error", Message: "The host was not found"})
				log.Println(err)
				return
			}
		} else if u.serviceID != "" {
			if err := db.C(server.C.Services).Update(bson.M{"projectId": pid, "_id": u.hostID}, bson.M{"$addToSet": bson.M{"files": lairFile}}); err != nil {
				server.R.JSON(w, http.StatusNotFound, &app.Response{Status: "Error", Message: "The service was not found"})
				log.Println(err)
				return
			}
		} else if u.issueID != "" {
			if err := db.C(server.C.Issues).Update(bson.M{"projectId": pid, "_id": u.hostID}, bson.M{"$addToSet": bson.M{"files": lairFile}}); err != nil {
				server.R.JSON(w, http.StatusNotFound, &app.Response{Status: "Error", Message: "The host was not found"})
				log.Println(err)
				return
			}
		} else {
			if err := db.C(server.C.Projects).Update(bson.M{"_id": pid}, bson.M{"$addToSet": bson.M{"files": lairFile}}); err != nil {
				server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Internal server error"})
				log.Println(err)
				return
			}
		}

		server.R.JSON(w, http.StatusCreated, &lairFile)
	}
}
