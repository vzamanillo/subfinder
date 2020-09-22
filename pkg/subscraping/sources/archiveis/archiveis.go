// Package archiveis is a Archiveis Scraping Engine in Golang
package archiveis

import (
	"context"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type agent struct {
	Results chan subscraping.Result
	Session *subscraping.Session
}

var reNext = regexp.MustCompile("<a id=\"next\" style=\".*\" href=\"(.*)\">&rarr;</a>")

func (a *agent) enumerate(ctx context.Context, baseURL string) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := a.Session.SimpleGet(ctx, baseURL)
	if err != nil {
		a.Results <- subscraping.Result{Source: sourcename, Type: subscraping.Error, Error: err}
		a.Session.DiscardHTTPResponse(resp)
		return
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		a.Results <- subscraping.Result{Source: sourcename, Type: subscraping.Error, Error: err}
		resp.Body.Close()
		return
	}

	resp.Body.Close()

	src := string(body)
	for _, subdomain := range a.Session.Extractor.FindAllString(src, -1) {
		a.Results <- subscraping.Result{Source: sourcename, Type: subscraping.Subdomain, Value: subdomain}
	}

	match1 := reNext.FindStringSubmatch(src)
	if len(match1) > 0 {
		a.enumerate(ctx, match1[1], sourcename)
	}
}

// Source is the passive scraping agent
type Source struct {
	Name string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	a := agent{
		Session: session,
		Results: results,
	}

	go func() {
		a.enumerate(ctx, fmt.Sprintf("http://archive.is/*.%s", domain))
		close(a.Results)
	}()

	return a.Results
}
