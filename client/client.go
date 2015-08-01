package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/lair-framework/go-lair"
)

const (
	importuri = "/api/projects/%s"
)

// Type used for defining the target Lair instance and auth creds
type LairTarget struct {
	User     string
	Password string
	Host     string
}

// Struct used to represent unmarshaled response from drone API server
type Response struct {
	Status  string
	Message string
}

// Creates a custom HTTP client used to talk with Lair Drone Server
func client() *http.Client {
	// Create a custom transport that ignores SSL errors
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

// Sends HTTP request to Lair API Server to import a project
func ImportProject(target *LairTarget, project *lair.Project) (*http.Response, error) {
	client := client()
	resource := fmt.Sprintf(importuri, project.ID)
	reqUrl := &url.URL{Host: target.Host, Path: resource, Scheme: "https"}

	body, err := json.Marshal(project)
	if err != nil {
		return nil, err
	}
	cb := ioutil.NopCloser(bytes.NewReader(body))

	header := make(http.Header)
	header.Add("Content-type", "application/json")

	req := &http.Request{Method: "PATCH", URL: reqUrl, Body: cb, ContentLength: int64(len(body)), Header: header}
	req.SetBasicAuth(target.User, target.Password)

	return client.Do(req)
}
