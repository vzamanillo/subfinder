package passive

import (
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/alienvault"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/anubis"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/archiveis"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/binaryedge"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/bufferover"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/cebaidu"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/censys"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/certspotter"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/certspotterold"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/chaos"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/crtsh"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/dnsdumpster"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/github"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/hackertarget"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/intelx"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/ipv4info"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/passivetotal"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/rapiddns"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/recon"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/riddler"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/robtex"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/spyse"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/sublist3r"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/threatbook"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/threatcrowd"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/threatminer"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/virustotal"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/waybackarchive"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/ximcx"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/zoomeye"
)

// DefaultSources contains the list of fast sources used by default.
var DefaultSources = []string{
	"alienvault",
	"anubis",
	"bufferover",
	"cebaidu",
	"certspotter",
	"certspotterold",
	"censys",
	"chaos",
	"crtsh",
	"dnsdumpster",
	"hackertarget",
	"intelx",
	"ipv4info",
	"passivetotal",
	"robtex",
	"riddler",
	"securitytrails",
	"shodan",
	"spyse",
	"sublist3r",
	"threatcrowd",
	"threatminer",
	"virustotal",
}

// DefaultRecursiveSources contains list of default recursive sources
var DefaultRecursiveSources = []string{
	"alienvault",
	"binaryedge",
	"bufferover",
	"cebaidu",
	"certspotter",
	"certspotterold",
	"crtsh",
	"dnsdumpster",
	"hackertarget",
	"ipv4info",
	"passivetotal",
	"securitytrails",
	"sublist3r",
	"virustotal",
	"ximcx",
}

// DefaultAllSources contains list of all sources
var DefaultAllSources = []string{
	"alienvault",
	"anubis",
	"archiveis",
	"binaryedge",
	"bufferover",
	"cebaidu",
	"censys",
	"certspotter",
	"certspotterold",
	"chaos",
	"commoncrawl",
	"crtsh",
	"dnsdumpster",
	"dnsdb",
	"github",
	"hackertarget",
	"ipv4info",
	"intelx",
	"passivetotal",
	"rapiddns",
	"riddler",
	"recon",
	"robtex",
	"securitytrails",
	"shodan",
	"sitedossier",
	"spyse",
	"sublist3r",
	"threatbook",
	"threatcrowd",
	"threatminer",
	"virustotal",
	"waybackarchive",
	"ximcx",
	"zoomeye",
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources map[string]subscraping.Source
}

// New creates a new agent for passive subdomain discovery
func New(sources, exclusions []string, keys *subscraping.Keys) *Agent {
	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: make(map[string]subscraping.Source)}

	agent.addSources(sources, keys)
	agent.removeSources(exclusions)

	return agent
}

// addSources adds the given list of sources to the source array
func (a *Agent) addSources(sources []string, keys *subscraping.Keys) {
	for _, source := range sources {
		switch source {
		case "alienvault":
			a.sources[source] = &alienvault.Source{Name: source}
		case "anubis":
			a.sources[source] = &anubis.Source{Name: source}
		case "archiveis":
			a.sources[source] = &archiveis.Source{Name: source}
		case "binaryedge":
			a.sources[source] = &binaryedge.Source{Name: source, Key: keys.BinaryEdge}
		case "bufferover":
			a.sources[source] = &bufferover.Source{Name: source}
		case "cebaidu":
			a.sources[source] = &cebaidu.Source{Name: source}
		case "censys":
			a.sources[source] = &censys.Source{
				Name: source,
				BasicAuth: &subscraping.BasicAuth{
					Username: keys.Censys.Token,
					Password: keys.Censys.Secret,
				},
			}
		case "certspotter":
			a.sources[source] = &certspotter.Source{Name: source, Token: keys.CertSpotter}
		case "certspotterold":
			a.sources[source] = &certspotterold.Source{Name: source}
		case "chaos":
			a.sources[source] = &chaos.Source{Name: source, Key: keys.Chaos}
		case "commoncrawl":
			a.sources[source] = &commoncrawl.Source{Name: source}
		case "crtsh":
			a.sources[source] = &crtsh.Source{Name: source}
		case "dnsdumpster":
			a.sources[source] = &dnsdumpster.Source{Name: source}
		case "dnsdb":
			a.sources[source] = &dnsdb.Source{Name: source, Key: keys.DNSDB}
		case "github":
			a.sources[source] = &github.Source{Name: source, Tokens: keys.GitHub.Tokens}
		case "hackertarget":
			a.sources[source] = &hackertarget.Source{Name: source}
		case "ipv4info":
			a.sources[source] = &ipv4info.Source{Name: source}
		case "intelx":
			a.sources[source] = &intelx.Source{
				Name: source,
				Host: keys.IntelX.Host,
				Key:  keys.IntelX.Key,
			}
		case "passivetotal":
			a.sources[source] = &passivetotal.Source{Name: source, BasicAuth: &keys.PassiveTotal.BasicAuth}
		case "rapiddns":
			a.sources[source] = &rapiddns.Source{Name: source}
		case "recon":
			a.sources[source] = &recon.Source{Name: source, Key: keys.Recon}
		case "riddler":
			a.sources[source] = &riddler.Source{Name: source}
		case "robtex":
			a.sources[source] = &robtex.Source{Name: source, Key: keys.Robtex}
		case "securitytrails":
			a.sources[source] = &securitytrails.Source{Name: source, Key: keys.SecurityTrails}
		case "shodan":
			a.sources[source] = &shodan.Source{Name: source, Key: keys.Shodan}
		case "sitedossier":
			a.sources[source] = &sitedossier.Source{Name: source}
		case "spyse":
			a.sources[source] = &spyse.Source{Name: source, Token: keys.Spyse}
		case "sublist3r":
			a.sources[source] = &sublist3r.Source{Name: source}
		case "threatbook":
			a.sources[source] = &threatbook.Source{Name: source, Key: keys.ThreatBook}
		case "threatcrowd":
			a.sources[source] = &threatcrowd.Source{Name: source}
		case "threatminer":
			a.sources[source] = &threatminer.Source{Name: source}
		case "virustotal":
			a.sources[source] = &virustotal.Source{Name: source, Key: keys.VirusTotal}
		case "waybackarchive":
			a.sources[source] = &waybackarchive.Source{Name: source}
		case "ximcx":
			a.sources[source] = &ximcx.Source{Name: source}
		case "zoomeye":
			a.sources[source] = &zoomeye.Source{Name: source, BasicAuth: &keys.ZoomEye.BasicAuth}
		}
	}
}

// removeSources deletes the given sources from the source map
func (a *Agent) removeSources(sources []string) {
	for _, source := range sources {
		delete(a.sources, source)
	}
}
