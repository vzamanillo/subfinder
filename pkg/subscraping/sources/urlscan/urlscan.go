package urlscan

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/m-mizutani/urlscan-go/urlscan"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.URLScan == "" {
			return
		}

		client := urlscan.NewClient(session.Keys.URLScan)
		task, err := client.Submit(urlscan.SubmitArguments{URL: fmt.Sprintf("https://%s", domain)})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		err = task.Wait()
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		data, err := jsoniter.Marshal(task.Result.Data)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		match := session.Extractor.FindAllString(string(data), -1)
		for _, m := range match {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: m}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "urlscan"
}
