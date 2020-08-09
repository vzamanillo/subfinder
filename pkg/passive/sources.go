package passive

import (
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/alienvault"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/archiveis"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/binaryedge"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/bufferover"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/censys"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/certspotter"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/certspotterold"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/crtsh"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/dnsdumpster"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/entrust"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/github"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/hackertarget"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/intelx"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/ipv4info"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/passivetotal"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/rapiddns"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/spyse"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/sublist3r"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/threatcrowd"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/threatminer"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/urlscan"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/virustotal"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/waybackarchive"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/zoomeye"
)

// DefaultSources contains the list of sources used by default
var DefaultSources = []string{
	"alienvault",
	"archiveis",
	"binaryedge",
	"bufferover",
	"censys",
	"certspotter",
	"certspotterold",
	"commoncrawl",
	"crtsh",
	"dnsdumpster",
	"dnsdb",
	"entrust",
	"github",
	"hackertarget",
	"ipv4info",
	"intelx",
	"passivetotal",
	"rapiddns",
	"securitytrails",
	"shodan",
	"sitedossier",
	"spyse",
	"sublist3r",
	"threatcrowd",
	"threatminer",
	"urlscan",
	"virustotal",
	"waybackarchive",
	"zoomeye",
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources map[string]subscraping.Source
	keys *subscraping.Keys
}

// New creates a new agent for passive subdomain discovery
func New(sources []string, exclusions []string, keys *subscraping.Keys) *Agent {
	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: make(map[string]subscraping.Source), keys: keys}

	agent.addSources(sources)
	agent.removeSources(exclusions)

	return agent
}

// addSources adds the given list of sources to the source array
func (a *Agent) addSources(sources []string) {
	for _, source := range sources {
		switch source {
		case "alienvault":
			a.sources[source] = &alienvault.Source{}
		case "archiveis":
			a.sources[source] = &archiveis.Source{}
		case "binaryedge":
			a.sources[source] = &binaryedge.Source{Key: a.keys.Binaryedge}
		case "bufferover":
			a.sources[source] = &bufferover.Source{}
		case "censys":
			a.sources[source] = &censys.Source{Token: a.keys.CensysToken, Secret: a.keys.CensysSecret}
		case "certspotter":
			a.sources[source] = &certspotter.Source{Token: a.keys.Certspotter}
		case "certspotterold":
			a.sources[source] = &certspotterold.Source{}
		case "commoncrawl":
			a.sources[source] = &commoncrawl.Source{}
		case "crtsh":
			a.sources[source] = &crtsh.Source{}
		case "dnsdumpster":
			a.sources[source] = &dnsdumpster.Source{}
		case "dnsdb":
			a.sources[source] = &dnsdb.Source{Key: a.keys.DNSDB}
		case "entrust":
			a.sources[source] = &entrust.Source{}
		case "github":
			a.sources[source] = &github.Source{Tokens: a.keys.GitHub}
		case "hackertarget":
			a.sources[source] = &hackertarget.Source{}
		case "ipv4info":
			a.sources[source] = &ipv4info.Source{}
		case "intelx":
			a.sources[source] = &intelx.Source{Host: a.keys.IntelXHost, Key: a.keys.IntelXKey}
		case "passivetotal":
			a.sources[source] = &passivetotal.Source{Username: a.keys.PassiveTotalUsername, Password: a.keys.PassiveTotalPassword}
		case "rapiddns":
			a.sources[source] = &rapiddns.Source{}
		case "securitytrails":
			a.sources[source] = &securitytrails.Source{Key: a.keys.Securitytrails}
		case "shodan":
			a.sources[source] = &shodan.Source{Key: a.keys.Shodan}
		case "sitedossier":
			a.sources[source] = &sitedossier.Source{}
		case "spyse":
			a.sources[source] = &spyse.Source{Token: a.keys.Spyse}
		case "sublist3r":
			a.sources[source] = &sublist3r.Source{}
		case "threatcrowd":
			a.sources[source] = &threatcrowd.Source{}
		case "threatminer":
			a.sources[source] = &threatminer.Source{}
		case "urlscan":
			a.sources[source] = &urlscan.Source{Key: a.keys.URLScan}
		case "virustotal":
			a.sources[source] = &virustotal.Source{Key: a.keys.Virustotal}
		case "waybackarchive":
			a.sources[source] = &waybackarchive.Source{}
		case "zoomeye":
			a.sources[source] = &zoomeye.Source{Username: a.keys.ZoomEyeUsername, Password: a.keys.ZoomEyePassword}
		}
	}
}

// removeSources deletes the given sources from the source map
func (a *Agent) removeSources(sources []string) {
	for _, source := range sources {
		delete(a.sources, source)
	}
}
