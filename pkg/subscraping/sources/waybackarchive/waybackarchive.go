package waybackarchive

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		pagesResp, err := session.SimpleGet(ctx, fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(pagesResp)
			close(results)
			return
		}

		defer pagesResp.Body.Close()

		scanner := bufio.NewScanner(pagesResp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			line, _ = url.QueryUnescape(line)
			match := session.Extractor.FindAllString(line, -1)
			for _, subdomain := range match {
				// fix for triple encoded URL
				subdomain = strings.ToLower(subdomain)
				subdomain = strings.TrimPrefix(subdomain, "25")
				subdomain = strings.TrimPrefix(subdomain, "2f")

				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		}

		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "waybackarchive"
}
