package runner

import (
	"math/rand"
	"os"
	"strings"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
	"gopkg.in/yaml.v3"
)

// OldConfigFile contains the fields stored in the configuration file prior to v2.4.5
type OldConfigFile struct {
	// Resolvers contains the list of resolvers to use while resolving
	Resolvers []string `yaml:"resolvers,omitempty"`
	// Sources contains a list of sources to use for enumeration
	Sources []string `yaml:"sources,omitempty"`
	// ExcludeSources contains the sources to not include in the enumeration process
	ExcludeSources []string `yaml:"exclude-sources,omitempty"`
	// API keys for different sources
	Binaryedge     []string `yaml:"binaryedge"`
	Censys         []string `yaml:"censys"`
	Certspotter    []string `yaml:"certspotter"`
	Chaos          []string `yaml:"chaos"`
	DNSDB          []string `yaml:"dnsdb"`
	GitHub         []string `yaml:"github"`
	IntelX         []string `yaml:"intelx"`
	PassiveTotal   []string `yaml:"passivetotal"`
	Recon          []string `yaml:"recon"`
	Robtex         []string `yaml:"robtex"`
	SecurityTrails []string `yaml:"securitytrails"`
	Shodan         []string `yaml:"shodan"`
	Spyse          []string `yaml:"spyse"`
	ThreatBook     []string `yaml:"threatbook"`
	URLScan        []string `yaml:"urlscan"`
	Virustotal     []string `yaml:"virustotal"`
	ZoomEye        []string `yaml:"zoomeye"`
	// Version indicates the version of subfinder installed.
	Version string `yaml:"subfinder-version"`
}

// OldKeys is the old keys format struct
type OldKeys struct {
	Binaryedge           string   `json:"binaryedge"`
	CensysToken          string   `json:"censysUsername"`
	CensysSecret         string   `json:"censysPassword"`
	Certspotter          string   `json:"certspotter"`
	Chaos                string   `json:"chaos"`
	DNSDB                string   `json:"dnsdb"`
	GitHub               []string `json:"github"`
	IntelXHost           string   `json:"intelXHost"`
	IntelXKey            string   `json:"intelXKey"`
	PassiveTotalUsername string   `json:"passivetotal_username"`
	PassiveTotalPassword string   `json:"passivetotal_password"`
	Recon                string   `json:"recon"`
	Robtex               string   `json:"robtex"`
	Securitytrails       string   `json:"securitytrails"`
	Shodan               string   `json:"shodan"`
	Spyse                string   `json:"spyse"`
	ThreatBook           string   `json:"threatbook"`
	URLScan              string   `json:"urlscan"`
	Virustotal           string   `json:"virustotal"`
	ZoomEyeUsername      string   `json:"zoomeye_username"`
	ZoomEyePassword      string   `json:"zoomeye_password"`
}

// GetMigratedKeys returns the new keys structure form the old one
func (c *OldConfigFile) GetMigratedKeys() *subscraping.Keys {
	oldKeys := c.GetKeys()

	newKeys := &subscraping.Keys{
		BinaryEdge:     oldKeys.Binaryedge,
		CertSpotter:    oldKeys.Certspotter,
		Chaos:          oldKeys.Chaos,
		DNSDB:          oldKeys.DNSDB,
		Recon:          oldKeys.Recon,
		Robtex:         oldKeys.Robtex,
		SecurityTrails: oldKeys.Securitytrails,
		Shodan:         oldKeys.Shodan,
		Spyse:          oldKeys.Spyse,
		ThreatBook:     oldKeys.ThreatBook,
		URLScan:        oldKeys.URLScan,
		VirusTotal:     oldKeys.Virustotal,
	}

	newKeys.Censys.Token = oldKeys.CensysToken
	newKeys.Censys.Secret = oldKeys.CensysSecret
	newKeys.GitHub.Tokens = oldKeys.GitHub
	newKeys.IntelX.Host = oldKeys.IntelXHost
	newKeys.IntelX.Key = oldKeys.IntelXKey
	newKeys.PassiveTotal.BasicAuth.Username = oldKeys.PassiveTotalUsername
	newKeys.PassiveTotal.BasicAuth.Password = oldKeys.PassiveTotalPassword
	newKeys.ZoomEye.BasicAuth.Username = oldKeys.ZoomEyeUsername
	newKeys.ZoomEye.BasicAuth.Password = oldKeys.ZoomEyePassword

	return newKeys
}

// GetKeys gets the API keys from config file and creates a Keys struct
// We use random selection of api keys from the list of keys supplied.
// Keys that require 2 options are separated by colon (:).
func (c *OldConfigFile) GetKeys() *OldKeys {
	keys := &OldKeys{}

	if len(c.Binaryedge) > 0 {
		keys.Binaryedge = c.Binaryedge[rand.Intn(len(c.Binaryedge))]
	}

	if len(c.Censys) > 0 {
		censysKeys := c.Censys[rand.Intn(len(c.Censys))]
		parts := strings.Split(censysKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.CensysToken = parts[0]
			keys.CensysSecret = parts[1]
		}
	}

	if len(c.Certspotter) > 0 {
		keys.Certspotter = c.Certspotter[rand.Intn(len(c.Certspotter))]
	}
	if len(c.Chaos) > 0 {
		keys.Chaos = c.Chaos[rand.Intn(len(c.Chaos))]
	}
	if (len(c.DNSDB)) > 0 {
		keys.DNSDB = c.DNSDB[rand.Intn(len(c.DNSDB))]
	}
	if (len(c.GitHub)) > 0 {
		keys.GitHub = c.GitHub
	}

	if len(c.IntelX) > 0 {
		intelxKeys := c.IntelX[rand.Intn(len(c.IntelX))]
		parts := strings.Split(intelxKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.IntelXHost = parts[0]
			keys.IntelXKey = parts[1]
		}
	}

	if len(c.PassiveTotal) > 0 {
		passiveTotalKeys := c.PassiveTotal[rand.Intn(len(c.PassiveTotal))]
		parts := strings.Split(passiveTotalKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.PassiveTotalUsername = parts[0]
			keys.PassiveTotalPassword = parts[1]
		}
	}

	if len(c.Recon) > 0 {
		keys.Recon = c.Recon[rand.Intn(len(c.Recon))]
	}

	if len(c.Robtex) > 0 {
		keys.Robtex = c.Robtex[rand.Intn(len(c.Robtex))]
	}

	if len(c.SecurityTrails) > 0 {
		keys.Securitytrails = c.SecurityTrails[rand.Intn(len(c.SecurityTrails))]
	}
	if len(c.Shodan) > 0 {
		keys.Shodan = c.Shodan[rand.Intn(len(c.Shodan))]
	}
	if len(c.Spyse) > 0 {
		keys.Spyse = c.Spyse[rand.Intn(len(c.Spyse))]
	}
	if len(c.ThreatBook) > 0 {
		keys.ThreatBook = c.ThreatBook[rand.Intn(len(c.ThreatBook))]
	}
	if len(c.URLScan) > 0 {
		keys.URLScan = c.URLScan[rand.Intn(len(c.URLScan))]
	}
	if len(c.Virustotal) > 0 {
		keys.Virustotal = c.Virustotal[rand.Intn(len(c.Virustotal))]
	}
	if len(c.ZoomEye) > 0 {
		zoomEyeKeys := c.ZoomEye[rand.Intn(len(c.ZoomEye))]
		parts := strings.Split(zoomEyeKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.ZoomEyeUsername = parts[0]
			keys.ZoomEyePassword = parts[1]
		}
	}

	return keys
}

// UnmarshalReadOld reads the unmarshalled config yaml file from disk
func UnmarshalReadOld(file string) (OldConfigFile, error) {
	config := OldConfigFile{}

	f, err := os.Open(file)
	if err != nil {
		return config, err
	}
	err = yaml.NewDecoder(f).Decode(&config)
	f.Close()
	return config, err
}
