package runner

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const maxNumCount = 2

// EnumerateSingleDomain performs subdomain enumeration against a single domain
func (r *Runner) EnumerateSingleDomain(ctx context.Context, domain, output string, appendToFile bool) error {
	gologger.Infof("Enumerating subdomains for %s\n", domain)

	// Check if the user has asked to remove wildcards explicitly.
	// If yes, create the resolution pool and get the wildcards for the current domain
	var resolutionPool *resolve.ResolutionPool
	if r.options.RemoveWildcard {
		resolutionPool = r.resolverClient.NewResolutionPool(r.options.Threads, r.options.RemoveWildcard)
		err := resolutionPool.InitWildcards(domain)
		if err != nil {
			// Log the error but don't quit.
			gologger.Warningf("Could not get wildcards for domain %s: %s\n", domain, err)
		}
	}

	// Run the passive subdomain enumeration
	now := time.Now()
	passiveResults := r.passiveAgent.EnumerateSubdomains(domain, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	// Create a unique map for filtering duplicate subdomains out
	uniqueMap := make(map[string]resolve.HostEntry)
	// Create a map to track sources for each host
	sourceMap := make(map[string]map[string]struct{})
	// Process the results in a separate goroutine
	go func() {
		for result := range passiveResults {
			switch result.Type {
			case subscraping.Error:
				gologger.Warningf("Could not run source %s: %s\n", result.Source, result.Error)
			case subscraping.Subdomain:
				// Validate the subdomain found and remove wildcards from
				if !strings.HasSuffix(result.Value, "."+domain) {
					continue
				}
				subdomain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")

				if _, ok := uniqueMap[subdomain]; !ok {
					sourceMap[subdomain] = make(map[string]struct{})

				}

				// Log the verbose message about the found subdomain per source
				if _, ok := sourceMap[subdomain][result.Source]; !ok{
					gologger.Verbosef("%s\n", result.Source, subdomain)
				}

				sourceMap[subdomain][result.Source] = struct{}{}

				// Check if the subdomain is a duplicate. If not,
				// send the subdomain for resolution.
				if _, ok := uniqueMap[subdomain]; ok {
					continue
				}

				hostEntry := resolve.HostEntry{Host: subdomain, Source: result.Source}

				uniqueMap[subdomain] = hostEntry

				// If the user asked to remove wildcard then send on the resolve
				// queue. Otherwise, if mode is not verbose print the results on
				// the screen as they are discovered.
				if r.options.RemoveWildcard {
					resolutionPool.Tasks <- hostEntry
				}
			}
		}
		// Close the task channel only if wildcards are asked to be removed
		if r.options.RemoveWildcard {
			close(resolutionPool.Tasks)
		}
		wg.Done()
	}()

	// If the user asked to remove wildcards, listen from the results
	// queue and write to the map. At the end, print the found results to the screen
	foundResults := make(map[string]resolve.Result)
	if r.options.RemoveWildcard {
		// Process the results coming from the resolutions pool
		for result := range resolutionPool.Results {
			switch result.Type {
			case resolve.Error:
				gologger.Warningf("Could not resolve host: %s\n", result.Error)
			case resolve.Subdomain:
				// Add the found subdomain to a map.
				if _, ok := foundResults[result.Host]; !ok {
					foundResults[result.Host] = result
				}
			}
		}
	}
	wg.Wait()

	outputter := NewOutputter(r.options.JSON)

	// If verbose mode was used, then now print all the
	// found subdomains on the screen together.
	var err error
	if r.options.HostIP {
		err = outputter.WriteHostIP(foundResults, os.Stdout)
	} else {
		if r.options.RemoveWildcard {
			err = outputter.WriteHostNoWildcard(foundResults, os.Stdout)
		} else {
			if r.options.CaptureSources {
				err = outputter.WriteSourceHost(sourceMap,os.Stdout)
			} else {
				err = outputter.WriteHost(uniqueMap, os.Stdout)
			}
		}
		if err != nil {
			gologger.Errorf("Could not verbose results for %s: %s\n", domain, err)
			return err
		}
	}
	if err != nil {
		gologger.Errorf("Could not verbose results for %s: %s\n", domain, err)
		return err
	}

	// Show found subdomain count in any case.
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()
	if r.options.RemoveWildcard {
		gologger.Infof("Found %d subdomains for %s in %s\n", len(foundResults), domain, duration)
	} else {
		gologger.Infof("Found %d subdomains for %s in %s\n", len(uniqueMap), domain, duration)
	}

	// In case the user has specified to upload to chaos, write everything to a temporary buffer and upload
	if r.options.ChaosUpload {
		var buf = &bytes.Buffer{}
		err := outputter.WriteForChaos(uniqueMap, buf)
		// If an error occurs, do not interrupt, continue to check if user specified an output file
		if err != nil {
			gologger.Errorf("Could not prepare results for chaos %s\n", err)
		} else {
			// no error in writing host output, upload to chaos
			err = r.UploadToChaos(ctx, buf)
			if err != nil {
				gologger.Errorf("Could not upload results to chaos %s\n", err)
			} else {
				gologger.Infof("Input processed successfully and subdomains with valid records will be updated to chaos dataset.\n")
			}
			// clear buffer
			buf.Reset()
		}
	}

	if output != "" {
		file, err := outputter.createFile(output, appendToFile)
		if err != nil {
			gologger.Errorf("Could not create file %s for %s: %s\n", output, domain, err)
			return err
		}

		defer file.Close()

		if r.options.HostIP {
			err = outputter.WriteHostIP(foundResults, file)
		} else {
			if r.options.RemoveWildcard {
				err = outputter.WriteHostNoWildcard(foundResults, file)
			} else {
				if r.options.CaptureSources {
					err = outputter.WriteSourceHost(sourceMap, file)
				} else {
					err = outputter.WriteHost(uniqueMap, file)
				}
			}
		}
		if err != nil {
			gologger.Errorf("Could not write results to file %s for %s: %s\n", output, domain, err)
			return err
		}
	}

	return nil
}
