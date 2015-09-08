package app

import (
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/jmcvetta/randutil"
	"github.com/kennygrant/sanitize"
	"github.com/lair-framework/go-lair"
	"github.com/mholt/binding"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type fileRequest struct {
	File      *multipart.FileHeader
	hostID    string
	serviceID string
	issueID   string
}

func (f *fileRequest) FieldMap(req *http.Request) binding.FieldMap {
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

var imgExts = map[string]bool{
	".jpg":  true,
	".png":  true,
	".jpeg": true,
}

func (a *App) ServeFile(w http.ResponseWriter, req *http.Request) {
	db := context.Get(req, "db").(*mgo.Database)
	if db == nil {
		a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Unable to connect to database"})
		return
	}
	vars := mux.Vars(req)
	pid, ok := vars["pid"]
	if !ok {
		a.R.JSON(w, http.StatusBadRequest, &Response{Status: "Error", Message: "Missing project id"})
		return
	}

	filename, ok := vars["filename"]
	if !ok {
		a.R.JSON(w, http.StatusBadRequest, &Response{Status: "Error", Message: "Missing filename"})
		return
	}
	projectQ := bson.M{"_id": pid, "files": bson.M{"$elemMatch": bson.M{"url": req.URL.Path}}}
	subQ := bson.M{"projectId": pid, "files": bson.M{"$elemMatch": bson.M{"url": req.URL.Path}}}
	p := lair.Project{}
	h := lair.Host{}
	s := lair.Service{}
	i := lair.Issue{}
	files := []lair.File{}
	selector := bson.M{"files": 1}
	if err := db.C(a.C.Projects).Find(projectQ).Select(selector).One(&p); err == nil {
		files = p.Files
	} else if err := db.C(a.C.Hosts).Find(subQ).Select(selector).One(&h); err == nil {
		files = h.Files
	} else if err := db.C(a.C.Services).Find(subQ).Select(selector).One(&s); err == nil {
		files = s.Files
	} else if err := db.C(a.C.Issues).Find(subQ).Select(selector).One(&i); err == nil {
		files = i.Files
	}
	if len(files) < 1 {
		a.R.JSON(w, http.StatusNotFound, &Response{Status: "Error", Message: "File not found"})
		return
	}
	file := lair.File{}
	for _, f := range files {
		if f.URL == req.URL.Path {
			file = f
			break
		}
	}
	if !imgExts[path.Ext(file.FileName)] {
		w.Header().Set("Content-Disposition", "attachment; filename="+file.FileName)
	}
	http.ServeFile(w, req, path.Join(a.Filepath, path.Clean(filename)))
}

func (a *App) UploadFile(w http.ResponseWriter, req *http.Request) {
	db := context.Get(req, "db").(*mgo.Database)
	if db == nil {
		a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Unable to connect to database"})
		return
	}
	vars := mux.Vars(req)
	pid, ok := vars["pid"]
	if !ok {
		a.R.JSON(w, http.StatusBadRequest, &Response{Status: "Error", Message: "Missing project id"})
		return
	}

	// Max 30 MB.
	binding.MaxMemory = 30000000

	u := &fileRequest{}
	if errs := binding.Bind(req, u); errs.Handle(w) {
		return
	}
	fh, err := u.File.Open()
	if err != nil {
		a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Internal server error"})
		return
	}
	randomValue, err := randutil.AlphaString(48)
	if err != nil {
		a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Internal server error"})
		return
	}
	uname := randomValue + path.Ext(path.Base(u.File.Filename))
	fname := path.Join(a.Filepath, uname)
	hf, err := os.Create(fname)
	if err != nil {
		a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Internal server error"})
		log.Println(err)
		return
	}
	if _, err := io.Copy(hf, fh); err != nil {
		a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Internal server error"})
		log.Println(err)
		return
	}

	fileURL := req.URL.Path + "/" + uname
	lairFile := lair.File{
		FileName: sanitize.Name(u.File.Filename),
		URL:      fileURL,
	}

	if u.hostID != "" {
		if err := db.C(a.C.Hosts).Update(bson.M{"projectId": pid, "_id": u.hostID}, bson.M{"$addToSet": bson.M{"files": lairFile}}); err != nil {
			a.R.JSON(w, http.StatusNotFound, &Response{Status: "Error", Message: "The host was not found"})
			log.Println(err)
			return
		}
	} else if u.serviceID != "" {
		if err := db.C(a.C.Services).Update(bson.M{"projectId": pid, "_id": u.hostID}, bson.M{"$addToSet": bson.M{"files": lairFile}}); err != nil {
			a.R.JSON(w, http.StatusNotFound, &Response{Status: "Error", Message: "The service was not found"})
			log.Println(err)
			return
		}
	} else if u.issueID != "" {
		if err := db.C(a.C.Issues).Update(bson.M{"projectId": pid, "_id": u.hostID}, bson.M{"$addToSet": bson.M{"files": lairFile}}); err != nil {
			a.R.JSON(w, http.StatusNotFound, &Response{Status: "Error", Message: "The host was not found"})
			log.Println(err)
			return
		}
	} else {
		if err := db.C(a.C.Projects).Update(bson.M{"_id": pid}, bson.M{"$addToSet": bson.M{"files": lairFile}}); err != nil {
			a.R.JSON(w, http.StatusInternalServerError, &Response{Status: "Error", Message: "Internal server error"})
			log.Println(err)
			return
		}
	}

	a.R.JSON(w, http.StatusCreated, &lairFile)
}
