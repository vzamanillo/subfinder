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
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/recon"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/spyse"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/sublist3r"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/threatcrowd"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/threatminer"
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
	"recon",
	"securitytrails",
	"shodan",
	"sitedossier",
	"spyse",
	"sublist3r",
	"threatcrowd",
	"threatminer",
	"virustotal",
	"waybackarchive",
	"zoomeye",
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources map[string]subscraping.Source
	keys    *subscraping.Keys
}

// New creates a new agent for passive subdomain discovery
func New(sources, exclusions []string, keys *subscraping.Keys) *Agent {
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
			a.sources[source] = &alienvault.Source{Name: source}
		case "archiveis":
			a.sources[source] = &archiveis.Source{Name: source}
		case "binaryedge":
			a.sources[source] = &binaryedge.Source{Name: source, Key: a.keys.BinaryEdge}
		case "bufferover":
			a.sources[source] = &bufferover.Source{Name: source}
		case "censys":
			a.sources[source] = &censys.Source{Name: source, BasicAuth: &a.keys.Censys.BasicAuth}
		case "certspotter":
			a.sources[source] = &certspotter.Source{Name: source, Token: a.keys.CertSpotter}
		case "certspotterold":
			a.sources[source] = &certspotterold.Source{Name: source}
		case "commoncrawl":
			a.sources[source] = &commoncrawl.Source{Name: source}
		case "crtsh":
			a.sources[source] = &crtsh.Source{Name: source}
		case "dnsdumpster":
			a.sources[source] = &dnsdumpster.Source{Name: source}
		case "dnsdb":
			a.sources[source] = &dnsdb.Source{Name: source, Key: a.keys.DNSDB}
		case "entrust":
			a.sources[source] = &entrust.Source{Name: source}
		case "github":
			a.sources[source] = &github.Source{Name: source, Tokens: a.keys.GitHub.Keys}
		case "hackertarget":
			a.sources[source] = &hackertarget.Source{Name: source}
		case "ipv4info":
			a.sources[source] = &ipv4info.Source{Name: source}
		case "intelx":
			a.sources[source] = &intelx.Source{
				Name: source,
				Host: a.keys.IntelX.Host,
				Key:  a.keys.IntelX.Key,
			}
		case "passivetotal":
			a.sources[source] = &passivetotal.Source{Name: source, BasicAuth: &a.keys.PassiveTotal.BasicAuth}
		case "rapiddns":
			a.sources[source] = &rapiddns.Source{Name: source}
		case "recon":
			a.sources[source] = &recon.Source{Name: source}
		case "securitytrails":
			a.sources[source] = &securitytrails.Source{Name: source, Key: a.keys.SecurityTrails}
		case "shodan":
			a.sources[source] = &shodan.Source{Name: source, Key: a.keys.Shodan}
		case "sitedossier":
			a.sources[source] = &sitedossier.Source{Name: source}
		case "spyse":
			a.sources[source] = &spyse.Source{Name: source, Token: a.keys.Spyse}
		case "sublist3r":
			a.sources[source] = &sublist3r.Source{Name: source}
		case "threatcrowd":
			a.sources[source] = &threatcrowd.Source{Name: source}
		case "threatminer":
			a.sources[source] = &threatminer.Source{Name: source}
		case "virustotal":
			a.sources[source] = &virustotal.Source{Name: source, Key: a.keys.VirusTotal}
		case "waybackarchive":
			a.sources[source] = &waybackarchive.Source{Name: source}
		case "zoomeye":
			a.sources[source] = &zoomeye.Source{Name: source, BasicAuth: &a.keys.ZoomEye.BasicAuth}
		}
	}
}

// removeSources deletes the given sources from the source map
func (a *Agent) removeSources(sources []string) {
	for _, source := range sources {
		delete(a.sources, source)
	}
}
