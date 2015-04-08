package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/context"
	"github.com/lair-framework/go-lair"
	"github.com/lair-framework/go-lair-drone"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	VERSION           = "0.1.0"
	DRONE_LOG_HISTORY = 500
)

type Version struct {
	Value string `bson:"version"`
}

// Import merges information from a drone into an exsting project provided by id.
func Import(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		R.JSON(w, http.StatusInternalServerError, &DroneResponse{Status: "Error", Message: "Unable to read request body"})
		return
	}
	var doc lairdrone.Project
	if err := json.Unmarshal(body, &doc); err != nil {
		R.JSON(w, http.StatusInternalServerError, &DroneResponse{Status: "Error", Message: err.Error()})
		return
	}

	db := context.Get(req, "db").(*mgo.Database)
	if db == nil {
		R.JSON(w, http.StatusInternalServerError, &DroneResponse{Status: "Error", Message: "Unable to connect to database"})
		return
	}

	// Start of import

	// Validate versions
	var v Version
	if err := db.C(VersionsColl).Find(nil).One(&v); err != nil || v.Value != VERSION {
		R.JSON(w, http.StatusInternalServerError, &DroneResponse{Status: "Error", Message: "Incompatible versions"})
		return
	}

	// Validate required fields
	if doc.ProjectId == "" || doc.Commands == nil || len(doc.Commands) <= 0 {
		R.JSON(w, http.StatusInternalServerError, &DroneResponse{Status: "Error", Message: "Missing required field or invalid format"})
		return
	}

	// Lookup project
	var project lair.Project
	pid := doc.ProjectId
	if err := db.C(ProjectsColl).FindId(doc.ProjectId).One(&project); err != nil {
		R.JSON(w, http.StatusInternalServerError, &DroneResponse{Status: "Error", Message: "Invalid project id"})
		return
	}

	// Append new commands
	for _, c := range doc.Commands {
		command := &lair.Command{
			Tool:    c.Tool,
			Command: c.Command,
		}
		project.Commands = append(project.Commands, *command)
	}
	// Append new notes
	for _, n := range doc.Notes {
		note := &lair.Note{
			Title:          n.Title,
			Content:        n.Content,
			LastModifiedBy: n.LastModifiedBy,
		}
		project.Notes = append(project.Notes, *note)
	}

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
	db.C(HostsColl).EnsureIndexKey("project_id", "string_addr")
	db.C(PortsColl).EnsureIndexKey("project_id", "host_id", "port", "protocol")
	db.C(VulnerabilitiesColl).EnsureIndexKey("project_id", "plugin_ids")

	for _, docHost := range doc.Hosts {
		host := &lair.Host{}
		knownHost := true
		// Determine if the host is already in database
		m := bson.M{"project_id": pid, "string_addr": docHost.StringAddr}
		if err := db.C(HostsColl).Find(m).One(&host); err != nil {
			knownHost = false
		}

		// Used for checking if the host values changed during import
		data := []byte(fmt.Sprintf("%+v", host))
		preMD5 := fmt.Sprintf("%x", md5.Sum(data))

		// Initialize basic host info
		host.ProjectId = pid
		host.Alive = docHost.Alive
		host.StringAddr = docHost.StringAddr
		host.LongAddr = IpToInt(net.ParseIP(host.StringAddr))

		if host.MacAddr == "" {
			host.MacAddr = docHost.MACAddr
		}

		// Append all host notes
		for _, note := range docHost.Notes {
			note := &lair.Note{
				Title:          note.Title,
				Content:        note.Content,
				LastModifiedBy: note.LastModifiedBy,
			}
			host.Notes = append(host.Notes, *note)
		}

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
		for _, docOS := range docHost.OperatingSystem {
			found := false
			for _, dbOS := range host.OS {
				if dbOS.Tool == docOS.Tool && dbOS.Fingerprint == docOS.Fingerprint {
					found = true
				}
			}
			if !found {
				host.OS = append(host.OS, lair.OS{Tool: docOS.Tool, Weight: docOS.Weight, Fingerprint: docOS.Fingerprint})
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
				if !IsValidStatus(docHost.Status) {
					host.Status = lair.StatusGrey
				}
			}

			// Upsert changes
			db.C(HostsColl).UpsertId(host.Id, host)

		}

		if !knownHost {
			msg := fmt.Sprintf("%s - New host found: %s", time.Now().String(), docHost.StringAddr)
			project.DroneLog = append(project.DroneLog, msg)
		}

		for _, docPort := range docHost.Ports {

			m := bson.M{
				"project_id": pid,
				"host_id":    host.Id,
				"port":       docPort.PortNum,
				"protocol":   docPort.Protocol,
			}
			// Determine if the host is already in database
			port := &lair.Port{}
			knownPort := true
			if err := db.C(PortsColl).Find(m).One(&port); err != nil {
				knownPort = false
			}

			// Used for tracking if changes were made to port
			data = []byte(fmt.Sprintf("%+v", port))
			preMD5 := fmt.Sprintf("%x", md5.Sum(data))

			port.HostId = host.Id
			port.ProjectId = pid
			port.Protocol = docPort.Protocol
			port.Port = docPort.PortNum
			port.Alive = docPort.Alive

			if port.Product == "" || port.Product == "unknown" {
				port.Product = docPort.Product
			}

			if port.Service == "" || port.Service == "unknown" {
				port.Service = docPort.Service
			}

			// Append all port notes
			for _, note := range docPort.Notes {
				note := &lair.Note{
					Title:          note.Title,
					Content:        note.Content,
					LastModifiedBy: note.LastModifiedBy,
				}
				port.Notes = append(port.Notes, *note)
			}

			// Append all credentials
			for _, cred := range docPort.Credentials {
				cred := &lair.Credential{
					Username: cred.Username,
					Password: cred.Password,
					Hash:     cred.Hash,
				}
				port.Credentials = append(port.Credentials, *cred)
			}

			if !knownPort {
				id := bson.NewObjectId().Hex()
				port.Id = id
				port.Status = docPort.Status
				if !IsValidStatus(port.Status) {
					port.Status = lair.StatusGrey
				}
				msg := fmt.Sprintf(
					"%s - New port found: %d/%s (%s)",
					time.Now().String(),
					docPort.PortNum,
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
				db.C(PortsColl).UpsertId(port.Id, port)
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
		if err := db.C(VulnerabilitiesColl).Find(m).One(&vuln); err != nil {
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
			vuln.Cvss = docVuln.CVSS
			vuln.Confirmed = docVuln.Confirmed
			vuln.Flag = docVuln.Flag
			vuln.LastModifiedBy = doc.Tool
			vuln.IdentifiedBy = []string{doc.Tool}
			vuln.Status = docVuln.Status
			if !IsValidStatus(vuln.Status) {
				vuln.Status = lair.StatusGrey
			}
			for _, plugin := range docVuln.PluginIds {
				vuln.PluginIds = append(vuln.PluginIds, lair.PluginId{Tool: plugin.Tool, Id: plugin.Id})
			}
			for _, cve := range docVuln.CVEs {
				vuln.Cves = append(vuln.Cves, cve)
			}
			for _, note := range docVuln.Notes {
				vuln.Notes = append(vuln.Notes, lair.Note{Title: note.Title, Content: note.Content})
			}
			for _, hk := range docVuln.Hosts {
				vuln.Hosts = append(
					vuln.Hosts,
					lair.VulnerabilityHost{StringAddr: hk.StringAddr, Port: hk.PortNum, Protocol: hk.Protocol},
				)
			}
			msg := fmt.Sprintf(
				"%s - New vulnerability found: %s",
				time.Now().String(),
				docVuln.Title,
			)
			project.DroneLog = append(project.DroneLog, msg)

			// Insert new vulnerability
			if err := db.C(VulnerabilitiesColl).Insert(vuln); err != nil {
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
			for _, docCVE := range docVuln.CVEs {
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
					if dbHk.StringAddr == hk.StringAddr && dbHk.Port == hk.PortNum && dbHk.Protocol == hk.Protocol {
						found = true
					}
				}
				if !found {
					vuln.Hosts = append(
						vuln.Hosts,
						lair.VulnerabilityHost{StringAddr: hk.StringAddr, Port: hk.PortNum, Protocol: hk.Protocol},
					)
					vuln.LastModifiedBy = doc.Tool
					msg := fmt.Sprintf(
						"%s - %s:%d/%s - New vulnerability found: %s",
						time.Now().String(),
						hk.StringAddr,
						hk.PortNum,
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
					vuln.PluginIds = append(
						vuln.PluginIds,
						lair.PluginId{Tool: docPlugin.Tool, Id: docPlugin.Id},
					)
					vuln.LastModifiedBy = doc.Tool
				}
			}

			// Append notes
			for _, n := range docVuln.Notes {
				note := &lair.Note{
					Title:          n.Title,
					Content:        n.Content,
					LastModifiedBy: n.LastModifiedBy,
				}
				vuln.Notes = append(vuln.Notes, *note)
			}

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
				db.C(VulnerabilitiesColl).UpsertId(vuln.Id, vuln)
			}
		}
	}

	// Ensure the correct drone log hisory size is maintained
	if len(project.DroneLog) > DRONE_LOG_HISTORY {
		project.DroneLog = project.DroneLog[len(project.DroneLog)-DRONE_LOG_HISTORY:]
	}

	// Update project
	db.C(ProjectsColl).UpdateId(project.Id, project)

	// End of import

	R.JSON(w, http.StatusOK, &DroneResponse{Status: "Ok"})
}
