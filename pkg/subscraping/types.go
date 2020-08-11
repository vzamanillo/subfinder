package subscraping

import (
	"context"
	"net/http"
	"regexp"
)

// BasicAuth request's Authorization header
type BasicAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Source is an interface inherited by each passive source
type Source interface {
	// Run takes a domain as argument and a session object
	// which contains the extractor for subdomains, http client
	// and other stuff.
	Run(context.Context, string, *Session) <-chan Result
}

// Session is the option passed to the source, an option is created
// uniquely for eac source.
type Session struct {
	// Extractor is the regex for subdomains created for each domain
	Extractor *regexp.Regexp
	// Client is the current http client
	Client *http.Client
}

// Keys contains the current API Keys we have in store
type Keys struct {
	BinaryEdge  string                        `json:"binaryedge"`
	Censys      struct{ BasicAuth BasicAuth } `json:"censys"`
	CertSpotter string                        `json:"certspotter"`
	Chaos       string                        `json:"chaos"`
	DNSDB       string                        `json:"dnsdb"`
	GitHub      struct {
		Tokens []string `json:"keys"`
	}
	IntelX struct {
		Host string `json:"host"`
		Key  string `json:"key"`
	} `json:"intelx"`
	PassiveTotal   struct{ BasicAuth BasicAuth } `json:"passivetotal"`
	SecurityTrails string                        `json:"securitytrails"`
	Shodan         string                        `json:"shodan"`
	ShodanDNSDB    string                        `json:"shodandnsdb"`
	Spyse          string                        `json:"spyse"`
	URLScan        string                        `json:"urlscan"`
	VirusTotal     string                        `json:"virustotal"`
	ZoomEye        struct{ BasicAuth BasicAuth } `json:"zoomeye"`
}

// Result is a result structure returned by a source
type Result struct {
	Type   ResultType
	Source string
	Value  string
	Error  error
}

// ResultType is the type of result returned by the source
type ResultType int

// Types of results returned by the source
const (
	Subdomain ResultType = iota
	Error
)
