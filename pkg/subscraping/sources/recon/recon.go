package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type subdomain struct {
	Domain    string `json:"domain"`
	IP        string `json:"ip"`
	RawDomain string `json:"rawDomain"`
	RawPort   string `json:"rawPort"`
	RawIP     string `json:"rawIp"`
}

// Source is the passive scraping agent
type Source struct {
	Name string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://api.recon.dev/search?domain=%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var subdomains []subdomain
		err = json.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, subdomain := range subdomains {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Subdomain, Value: subdomain.RawDomain}
		}
	}()

	return results
}
