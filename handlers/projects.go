package handlers

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/lair-framework/api-server/app"
	"github.com/lair-framework/api-server/lib/ip"
	"github.com/lair-framework/api-server/middleware"
	"github.com/lair-framework/go-lair"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// Add/update a project using additive, smart merge
func UpdateProject(server *app.App) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to read request body"})
			return
		}
		var doc lair.Project
		if err := json.Unmarshal(body, &doc); err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: err.Error()})
			return
		}

		db := context.Get(req, "db").(*mgo.Database)
		if db == nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to connect to database"})
			return
		}

		// Start of import

		// Validate versions
		var v lair.Version
		if err := db.C(server.C.Versions).Find(nil).One(&v); err != nil || v.Value != server.Version {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Incompatible versions"})
			return
		}

		// Validate required fields
		if doc.Id == "" || doc.Commands == nil || len(doc.Commands) <= 0 {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Missing required field or invalid format"})
			return
		}

		// Lookup project
		var project lair.Project
		pid := doc.Id
		if err := db.C(server.C.Projects).FindId(doc.Id).One(&project); err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Invalid project id"})
			return
		}

		// Append new commands
		project.Commands = append(project.Commands, doc.Commands...)

		// Append new notes
		project.Notes = append(project.Notes, doc.Notes...)

		// Add owner if necessary
		if project.Owner == "" {
			project.Owner = doc.Owner
		}

		// Add industry if necessary
		if project.Industry == "" {
			project.Industry = doc.Industry
		}

		// Add creation date if necessary
		if project.CreationDate == "" {
			project.CreationDate = doc.CreationDate
		}

		// Add description if necessary
		if project.Description == "" {
			project.Description = doc.Description
		}

		// Ensure indexes
		db.C(server.C.Hosts).EnsureIndexKey("project_id", "string_addr")
		db.C(server.C.Ports).EnsureIndexKey("project_id", "host_id", "port", "protocol")
		db.C(server.C.Vulnerabilities).EnsureIndexKey("project_id", "plugin_ids")

		for _, docHost := range doc.Hosts {
			host := &lair.Host{}
			knownHost := true
			// Determine if the host is already in database
			m := bson.M{"project_id": pid, "string_addr": docHost.StringAddr}
			if err := db.C(server.C.Hosts).Find(m).One(&host); err != nil {
				knownHost = false
			}

			// Used for checking if the host values changed during import
			data := []byte(fmt.Sprintf("%+v", host))
			preMD5 := fmt.Sprintf("%x", md5.Sum(data))

			// Initialize basic host info
			host.ProjectId = pid
			host.Alive = docHost.Alive
			host.StringAddr = docHost.StringAddr
			host.LongAddr = ip.IpToInt(net.ParseIP(host.StringAddr))

			if host.MacAddr == "" {
				host.MacAddr = docHost.MacAddr
			}

			// Append all host notes
			host.Notes = append(host.Notes, docHost.Notes...)

			// Add any new hostnames
			for _, docHostname := range docHost.Hostnames {
				found := false
				for _, dbHostname := range host.Hostnames {
					if dbHostname == docHostname {
						found = true
					}
				}
				if !found {
					host.Hostnames = append(host.Hostnames, docHostname)
					host.LastModifiedBy = doc.Tool
				}
			}

			// Add any new OSes
			for _, docOS := range docHost.OS {
				found := false
				for _, dbOS := range host.OS {
					if dbOS.Tool == docOS.Tool && dbOS.Fingerprint == docOS.Fingerprint {
						found = true
					}
				}
				if !found {
					host.OS = append(host.OS, docOS)
					host.LastModifiedBy = doc.Tool
				}
			}

			data = []byte(fmt.Sprintf("%+v", host))
			postMD5 := fmt.Sprintf("%x", md5.Sum(data))

			// Check if host was changed
			if preMD5 != postMD5 {
				host.LastModifiedBy = doc.Tool
				if !knownHost {
					id := bson.NewObjectId().Hex()
					host.Id = id
					host.Status = docHost.Status
					if !server.IsValidStatus(docHost.Status) {
						host.Status = lair.StatusGrey
					}
				}

				// Upsert changes
				db.C(server.C.Hosts).UpsertId(host.Id, host)

			}

			if !knownHost {
				msg := fmt.Sprintf("%s - New host found: %s", time.Now().String(), docHost.StringAddr)
				project.DroneLog = append(project.DroneLog, msg)
			}

			for _, docPort := range docHost.Ports {

				m := bson.M{
					"project_id": pid,
					"host_id":    host.Id,
					"port":       docPort.Port,
					"protocol":   docPort.Protocol,
				}
				// Determine if the host is already in database
				port := &lair.Port{}
				knownPort := true
				if err := db.C(server.C.Ports).Find(m).One(&port); err != nil {
					knownPort = false
				}

				// Used for tracking if changes were made to port
				data = []byte(fmt.Sprintf("%+v", port))
				preMD5 := fmt.Sprintf("%x", md5.Sum(data))

				port.HostId = host.Id
				port.ProjectId = pid
				port.Protocol = docPort.Protocol
				port.Port = docPort.Port
				port.Alive = docPort.Alive

				if port.Product == "" || port.Product == "unknown" {
					port.Product = docPort.Product
				}

				if port.Service == "" || port.Service == "unknown" {
					port.Service = docPort.Service
				}

				// Append all port notes
				port.Notes = append(port.Notes, docPort.Notes...)

				// Append all credentials
				port.Credentials = append(port.Credentials, docPort.Credentials...)

				if !knownPort {
					id := bson.NewObjectId().Hex()
					port.Id = id
					port.Status = docPort.Status
					if !server.IsValidStatus(port.Status) {
						port.Status = lair.StatusGrey
					}
					msg := fmt.Sprintf(
						"%s - New port found: %d/%s (%s)",
						time.Now().String(),
						docPort.Port,
						docPort.Protocol,
						docPort.Service,
					)
					project.DroneLog = append(project.DroneLog, msg)
				}

				// Used for tracking if changes were made to port
				data = []byte(fmt.Sprintf("%+v", port))
				postMD5 = fmt.Sprintf("%x", md5.Sum(data))

				// Upsert any changes
				if preMD5 != postMD5 {
					port.LastModifiedBy = doc.Tool
					db.C(server.C.Ports).UpsertId(port.Id, port)
				}
			}
		}

		for _, docVuln := range doc.Vulnerabilities {
			pluginM := bson.M{
				"$all": docVuln.PluginIds,
			}
			m := bson.M{
				"project_id": pid,
				"plugin_ids": pluginM,
			}
			// Check if vulnerability already exists
			vuln := &lair.Vulnerability{}
			knownVuln := true
			if err := db.C(server.C.Vulnerabilities).Find(m).One(&vuln); err != nil {
				knownVuln = false
			}

			if !knownVuln {
				id := bson.NewObjectId().Hex()
				vuln.Id = id
				vuln.ProjectId = pid
				vuln.Title = docVuln.Title
				vuln.Description = docVuln.Description
				vuln.Solution = docVuln.Solution
				vuln.Evidence = docVuln.Evidence
				vuln.Cvss = docVuln.Cvss
				vuln.Confirmed = docVuln.Confirmed
				vuln.Flag = docVuln.Flag
				vuln.LastModifiedBy = doc.Tool
				vuln.IdentifiedBy = []string{doc.Tool}
				vuln.Status = docVuln.Status
				if !server.IsValidStatus(vuln.Status) {
					vuln.Status = lair.StatusGrey
				}
				vuln.PluginIds = docVuln.PluginIds
				vuln.Cves = docVuln.Cves
				vuln.Notes = docVuln.Notes
				vuln.Hosts = docVuln.Hosts
				msg := fmt.Sprintf(
					"%s - New vulnerability found: %s",
					time.Now().String(),
					docVuln.Title,
				)
				project.DroneLog = append(project.DroneLog, msg)

				// Insert new vulnerability
				if err := db.C(server.C.Vulnerabilities).Insert(vuln); err != nil {
					// TODO: How to handle failed vuln insert?
				}
			}

			if knownVuln {

				// Used for tracking if changes were made to vulnerability
				data := []byte(fmt.Sprintf("%+v", vuln))
				preMD5 := fmt.Sprintf("%x", md5.Sum(data))

				vuln.Title = docVuln.Title
				vuln.Description = docVuln.Description
				vuln.Solution = docVuln.Solution
				if vuln.Evidence != docVuln.Evidence {
					vuln.Evidence = vuln.Evidence + "\n\n" + docVuln.Evidence
				}

				// Add any new CVEs
				for _, docCVE := range docVuln.Cves {
					found := false
					for _, dbCVE := range vuln.Cves {
						if dbCVE == docCVE {
							found = true
						}
					}
					if !found {
						vuln.Cves = append(vuln.Cves, docCVE)
						vuln.LastModifiedBy = doc.Tool
					}
				}

				// Add any new hosts
				for _, hk := range docVuln.Hosts {
					found := false
					for _, dbHk := range vuln.Hosts {
						if dbHk.StringAddr == hk.StringAddr && dbHk.Port == hk.Port && dbHk.Protocol == hk.Protocol {
							found = true
						}
					}
					if !found {
						vuln.Hosts = append(vuln.Hosts, hk)
						vuln.LastModifiedBy = doc.Tool
						msg := fmt.Sprintf(
							"%s - %s:%d/%s - New vulnerability found: %s",
							time.Now().String(),
							hk.StringAddr,
							hk.Port,
							hk.Protocol,
							docVuln.Title,
						)
						project.DroneLog = append(project.DroneLog, msg)
					}
				}

				// Add any new plugins
				for _, docPlugin := range docVuln.PluginIds {
					found := false
					for _, dbPlugin := range vuln.PluginIds {
						if dbPlugin.Tool == docPlugin.Tool && dbPlugin.Id == docPlugin.Id {
							found = true
						}
					}
					if !found {
						vuln.PluginIds = append(vuln.PluginIds, docPlugin)
						vuln.LastModifiedBy = doc.Tool
					}
				}

				// Append notes
				vuln.Notes = append(vuln.Notes, docVuln.Notes...)

				// Add any new 'Identified By' info
				found := false
				for _, idBy := range vuln.IdentifiedBy {
					if idBy == doc.Tool {
						found = true
					}
				}
				if !found {
					vuln.IdentifiedBy = append(vuln.IdentifiedBy, doc.Tool)
					vuln.LastModifiedBy = doc.Tool
				}

				// Only set flag to 'true', don't unset it
				if docVuln.Flag {
					vuln.Flag = true
				}

				// Only set confirmed to 'true', don't unset it
				if docVuln.Confirmed {
					vuln.Confirmed = true
				}

				// Check if vuln data was changed
				data = []byte(fmt.Sprintf("%+v", vuln))
				postMD5 := fmt.Sprintf("%x", md5.Sum(data))

				if preMD5 != postMD5 {
					// Upsert changes
					vuln.LastModifiedBy = doc.Tool
					db.C(server.C.Vulnerabilities).UpsertId(vuln.Id, vuln)
				}
			}
		}

		// Ensure the correct drone log hisory size is maintained
		if len(project.DroneLog) > server.History {
			project.DroneLog = project.DroneLog[len(project.DroneLog)-server.History:]
		}

		// Update project
		db.C(server.C.Projects).UpdateId(project.Id, project)

		// End of import

		server.R.JSON(w, http.StatusOK, &app.Response{Status: "Ok"})
	}
}

// Retrieve a single project
func ShowProject(server *app.App) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		db := context.Get(req, "db").(*mgo.Database)
		if db == nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to access database"})
			return
		}

		vars := mux.Vars(req)
		pid := vars["pid"]
		project := &lair.Project{}
		if err := db.C(server.C.Projects).FindId(pid).One(&project); err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to retrieve project or project does not exist"})
			return
		}

		server.R.JSON(w, http.StatusOK, project)
	}
}

// Retrieve a list of all projects that a user owns or is a contributor for
func IndexProject(server *app.App) func(w http.ResponseWriter, req *http.Request) {
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

		// Ensure query is restricted to only projects to which the user is authorized
		or := &bson.M{
			"$or": []bson.M{
				bson.M{"owner": user.Id},
				bson.M{"contributors": user.Id},
			},
		}
		var projects []lair.Project
		if err := db.C(server.C.Projects).Find(or).All(&projects); err != nil {
			server.R.JSON(w, http.StatusInternalServerError, &app.Response{Status: "Error", Message: "Unable to retrieve project index"})
			return
		}
		server.R.JSON(w, http.StatusOK, projects)
	}
}
