package runner

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/pkg/resolve"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
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
	uniqueMap := make(map[string]struct{})
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

				// Check if the subdomain is a duplicate. If not,
				// send the subdomain for resolution.
				if _, ok := uniqueMap[subdomain]; ok {
					continue
				}
				uniqueMap[subdomain] = struct{}{}

				// Log the verbose message about the found subdomain and send the
				// host for resolution to the resolution pool
				gologger.Verbosef("%s\n", result.Source, subdomain)

				// If the user asked to remove wildcard then send on the resolve
				// queue. Otherwise, if mode is not verbose print the results on
				// the screen as they are discovered.
				if r.options.RemoveWildcard {
					resolutionPool.Tasks <- subdomain
				}

				if !r.options.Verbose {
					gologger.Silentf("%s\n", subdomain)
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
	foundResults := make(map[string]string)
	if r.options.RemoveWildcard {
		// Process the results coming from the resolutions pool
		for result := range resolutionPool.Results {
			switch result.Type {
			case resolve.Error:
				gologger.Warningf("Could not resolve host: %s\n", result.Error)
			case resolve.Subdomain:
				// Add the found subdomain to a map.
				if _, ok := foundResults[result.Host]; !ok {
					foundResults[result.Host] = result.IP
				}
			}
		}
	}
	wg.Wait()

	// If verbose mode was used, then now print all the
	// found subdomains on the screen together.
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()
	if r.options.Verbose {
		if r.options.RemoveWildcard {
			for result := range foundResults {
				gologger.Silentf("%s\n", result)
			}
		} else {
			for result := range uniqueMap {
				gologger.Silentf("%s\n", result)
			}
		}
	}

	// Show found subdomain count in any case.
	if r.options.RemoveWildcard {
		gologger.Infof("Found %d subdomains for %s in %s\n", len(foundResults), domain, duration)
	} else {
		gologger.Infof("Found %d subdomains for %s in %s\n", len(uniqueMap), domain, duration)
	}

	outputter := &OutPutter{}

	// In case the user has specified to upload to chaos, write everything to a temporary buffer and upload
	if r.options.ChaosUpload {
		var buf = &bytes.Buffer{}
		err := outputter.WriteHost(uniqueMap, buf)
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
		file, err := outputter.createFile(output, r.options.OutputDirectory, r.options.JSON, appendToFile)
		if err != nil {
			gologger.Errorf("Could not create file %s for %s: %s\n", output, domain, err)
			return err
		}

		defer file.Close()

		if r.options.HostIP {
			err = outputter.WriteHostIP(foundResults, file)
		} else if r.options.JSON {
			err = outputter.WriteJSON(foundResults, file)
		} else {
			if r.options.RemoveWildcard {
				err = outputter.WriteHostNoWildcard(foundResults, file)
			} else {
				err = outputter.WriteHost(uniqueMap, file)
			}
		}
		if err != nil {
			gologger.Errorf("Could not write results to file %s for %s: %s\n", output, domain, err)
		}
		return err
	}

	return nil
}
