package certspotterold

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type subdomain struct {
	DNSNames []string `json:"dns_names"`
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

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://certspotter.com/api/v0/certs?domain=%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var subdomains []subdomain
		err = jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, subdomain := range subdomains {
			for _, dnsname := range subdomain.DNSNames {
				results <- subscraping.Result{Source: s.Name, Type: subscraping.Subdomain, Value: dnsname}
			}
		}
	}()
	return results
}
