package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/lair-framework/go-lair"
)

const (
	importuri = "/api/projects/%s"
)

// C is a Lair API client.
type C struct {
	User      string
	Password  string
	Host      string
	Scheme    string
	Transport *http.Transport
}

// COptions are used to pass options for setting up a new C.
type COptions struct {
	User               string
	Password           string
	Host               string
	Scheme             string
	InsecureSkipVerify bool
}

// New sets up and returns a new C.
func New(opts *COptions) (*C, error) {
	c := &C{
		User:      opts.User,
		Password:  opts.Password,
		Host:      opts.Host,
		Scheme:    opts.Scheme,
		Transport: &http.Transport{},
	}
	if c.User == "" {
		return c, errors.New("User can not be empty")
	}
	if c.Password == "" {
		return c, errors.New("Password can not be empty")
	}
	if c.Host == "" {
		return c, errors.New("Host can not be empty")
	}
	if c.Scheme == "" {
		c.Scheme = "https"
	}
	if c.Scheme == "https" {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify},
		}
	}
	return c, nil
}

// Response used to represent unmarshaled response from drone API server.
type Response struct {
	Status  string
	Message string
}

// DOptions are used to pass options to various requst to the Lair API.
type DOptions struct {
	ForcePorts bool
}

// ImportProject sends an HTTP request to Lair API Server to import a project.
func (c *C) ImportProject(opts *DOptions, project *lair.Project) (*http.Response, error) {
	client := &http.Client{Transport: c.Transport}
	resource := fmt.Sprintf(importuri, project.ID)
	reqURL := &url.URL{Host: c.Host, Path: resource, Scheme: c.Scheme}
	if opts.ForcePorts {
		reqURL.Query().Add("force-ports", "true")
	}
	body, err := json.Marshal(project)
	if err != nil {
		return nil, err
	}
	cb := ioutil.NopCloser(bytes.NewReader(body))
	header := make(http.Header)
	header.Add("Content-type", "application/json")
	req := &http.Request{Method: "PATCH", URL: reqURL, Body: cb, ContentLength: int64(len(body)), Header: header}
	req.SetBasicAuth(c.User, c.Password)
	return client.Do(req)
}
