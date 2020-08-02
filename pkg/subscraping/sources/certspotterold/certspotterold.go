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
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://certspotter.com/api/v0/certs?domain=%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			close(results)
			return
		}

		defer resp.Body.Close()

		var subdomains []subdomain
		err = jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		for _, subdomain := range subdomains {
			for _, dnsname := range subdomain.DNSNames {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: dnsname}
			}
		}

		close(results)
	}()
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "certspotterold"
}
