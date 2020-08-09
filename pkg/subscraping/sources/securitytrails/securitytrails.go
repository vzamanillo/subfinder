package securitytrails

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type response struct {
	Subdomains []string `json:"subdomains"`
}

// Source is the passive scraping agent
type Source struct {
	Name string
	Key  string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if s.Key == "" {
			return
		}

		resp, err := session.Get(ctx, fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain), "", map[string]string{"APIKEY": s.Key})
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var securityTrailsResponse response
		err = jsoniter.NewDecoder(resp.Body).Decode(&securityTrailsResponse)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, subdomain := range securityTrailsResponse.Subdomains {
			if strings.HasSuffix(subdomain, ".") {
				subdomain += domain
			} else {
				subdomain = subdomain + "." + domain
			}

			results <- subscraping.Result{Source: s.Name, Type: subscraping.Subdomain, Value: subdomain}
		}
	}()

	return results
}
