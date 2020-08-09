package ipv4info

import (
	"context"
	"io/ioutil"
	"regexp"
	"strconv"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	Name string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, "http://ipv4info.com/search/"+domain)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		src := string(body)
		regxTokens := regexp.MustCompile("/ip-address/(.*)/" + domain)
		matchTokens := regxTokens.FindAllString(src, -1)

		if len(matchTokens) == 0 {
			return
		}

		token := matchTokens[0]

		resp, err = session.SimpleGet(ctx, "http://ipv4info.com"+token)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}
		resp.Body.Close()

		src = string(body)
		regxTokens = regexp.MustCompile("/dns/(.*?)/" + domain)
		matchTokens = regxTokens.FindAllString(src, -1)
		if len(matchTokens) == 0 {
			return
		}

		token = matchTokens[0]
		resp, err = session.SimpleGet(ctx, "http://ipv4info.com"+token)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		src = string(body)
		regxTokens = regexp.MustCompile("/subdomains/(.*?)/" + domain)
		matchTokens = regxTokens.FindAllString(src, -1)
		if len(matchTokens) == 0 {
			return
		}

		token = matchTokens[0]
		resp, err = session.SimpleGet(ctx, "http://ipv4info.com"+token)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		src = string(body)
		for _, match := range session.Extractor.FindAllString(src, -1) {
			results <- subscraping.Result{Source: s.Name, Type: subscraping.Subdomain, Value: match}
		}
		nextPage := 1

		for {
			further := s.getSubdomains(ctx, domain, &nextPage, src, session, results)
			if !further {
				break
			}
		}
	}()

	return results
}

func (s *Source) getSubdomains(ctx context.Context, domain string, nextPage *int, src string, session *subscraping.Session, results chan subscraping.Result) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		default:
			regxTokens := regexp.MustCompile("/subdomains/.*/page" + strconv.Itoa(*nextPage) + "/" + domain + ".html")
			matchTokens := regxTokens.FindAllString(src, -1)
			if len(matchTokens) == 0 {
				return false
			}
			token := matchTokens[0]

			resp, err := session.SimpleGet(ctx, "http://ipv4info.com"+token)
			if err != nil {
				results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
				return false
			}
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				results <- subscraping.Result{Source: s.Name, Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return false
			}
			resp.Body.Close()
			src = string(body)
			for _, match := range session.Extractor.FindAllString(src, -1) {
				results <- subscraping.Result{Source: s.Name, Type: subscraping.Subdomain, Value: match}
			}
			*nextPage++
			return true
		}
	}
}
