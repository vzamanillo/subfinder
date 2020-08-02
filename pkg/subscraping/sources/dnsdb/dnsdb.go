package dnsdb

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type dnsdbResponse struct {
	Name string `json:"rrname"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.DNSDB == "" {
			return
		}

		headers := map[string]string{
			"X-API-KEY":    session.Keys.DNSDB,
			"Accept":       "application/json",
			"Content-Type": "application/json",
		}

		resp, err := session.Get(ctx, fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s?limit=1000000000000", domain), "", headers)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			var out dnsdbResponse
			err = jsoniter.NewDecoder(bytes.NewBufferString(line)).Decode(&out)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: strings.TrimSuffix(out.Name, ".")}
		}
	}()
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "DNSDB"
}
