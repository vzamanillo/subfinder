package sitedossier

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
	"time"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// SleepRandIntn is the integer value to get the pseudo-random number
// to sleep before find the next match
const SleepRandIntn = 5

var reNext = regexp.MustCompile(`<a href="([A-Za-z0-9/.]+)"><b>`)

type agent struct {
	results chan subscraping.Result
	session *subscraping.Session
}

func (a *agent) enumerate(ctx context.Context, baseURL, sourcename string) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			resp, err := a.session.SimpleGet(ctx, baseURL)
			if err != nil {
				a.results <- subscraping.Result{Source: sourcename, Type: subscraping.Error, Error: err}
				a.session.DiscardHTTPResponse(resp)
				close(a.results)
				return err
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				a.results <- subscraping.Result{Source: sourcename, Type: subscraping.Error, Error: err}
				resp.Body.Close()
				close(a.results)
				return err
			}
			resp.Body.Close()

			src := string(body)
			for _, match := range a.session.Extractor.FindAllString(src, -1) {
				a.results <- subscraping.Result{Source: sourcename, Type: subscraping.Subdomain, Value: match}
			}

			match1 := reNext.FindStringSubmatch(src)
			time.Sleep(time.Duration((3 + rand.Intn(SleepRandIntn))) * time.Second)

			if len(match1) > 0 {
				err := a.enumerate(ctx, "http://www.sitedossier.com"+match1[1], sourcename)
				if err != nil {
					return err
				}
			}
			return nil
		}
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
		session: session,
		results: results,
	}

	go func() {
		err := a.enumerate(ctx, fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain), s.Name)
		if err == nil {
			close(a.results)
		}
	}()
	return results
}
