package shodan

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

type dnsdbLookupResponse struct {
	Domain string `json:"domain"`
	Data   []struct {
		Subdomain string `json:"subdomain"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"data"`
	Result int    `json:"result"`
	Error  string `json:"error"`
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

		searchURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, session.Keys.Shodan)
		resp, err := session.SimpleGet(ctx, searchURL)
		if err != nil {
			session.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		var response dnsdbLookupResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		if response.Error != "" {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%v", response.Error)}
			return
		}

		for _, data := range response.Data {
			if data.Subdomain != "" {
				if data.Type == "CNAME" {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: data.Value}
				} else if data.Type == "A" {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: fmt.Sprintf("%s.%s", data.Subdomain, domain)}
				}
			}
		}
	}()

	return results
}
