<h1 align="left">
  <img src="static/subfinder-logo.png" alt="subfinder" width="170px"></a>
  <br>
</h1>


[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectdiscovery/subfinder)](https://goreportcard.com/report/github.com/projectdiscovery/subfinder)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectdiscovery/subfinder/issues)


subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources. It has a simple modular architecture and is optimized for speed. subfinder is built for doing one thing only - passive subdomain enumeration, and it does that very well.

We have designed subfinder to comply with all passive sources licenses, and usage restrictions, as well as maintained a consistently passive model to make it useful to both penetration testers and bug bounty hunters alike.


# Resources
- [Features](#features)
- [Usage](#usage)
- [Installation Instuctions (direct)](#direct-installation)
- [Installation Instructions](#installation-instructions)
    - [From Binary](#from-binary)
    - [From Source](#from-source)
    - [From Github](#from-github)
- [Upgrading](#upgrading)
- [Post Installation Instructions](#post-installation-instructions)
- [Running subfinder](#running-subfinder)
- [Running in a Docker Container](#running-in-a-docker-container)


 # Features

<h1 align="left">
  <img src="static/subfinder-run.png" alt="subfinder" width="700px"></a>
  <br>
</h1>


 - Simple and modular code base making it easy to contribute.
 - Fast And Powerful Resolution and wildcard elimination module
 - **Curated** passive sources to maximize results (26 Sources as of now)
 - Multiple Output formats supported (Json, File, Stdout)
 - Optimized for speed, very fast and **lightweight** on resources
 - **Stdin** and **stdout** support for integrating in workflows


# Usage

```bash
subfinder -h
```
This will display help for the tool. Here are all the switches it supports.

| Flag | Description | Example |
|------|-------------|---------|
| -cd | Upload results to the Chaos API (api-key required) | subfinder -d uber.com -cd |
| -config string | Configuration file for API Keys, etc  | subfinder -config config.yaml |
| -d | Domain to find subdomains for | subfinder -d uber.com |
| -dL  | File containing list of domains to enumerate | subfinder -dL hackerone-hosts.txt |
| -exclude-sources | List of sources to exclude from enumeration | subfinder -exclude-sources archiveis |
| -max-time | Minutes to wait for enumeration results (default 10) | subfinder -max-time 1 |
| -nC | Don't Use colors in output | subfinder -nC |
| -nW | Remove Wildcard & Dead Subdomains from output | subfinder -nW |
| -ls | List all available sources | subfinder -ls |
| -o  | File to write output to (optional) | subfinder -o output.txt |
| -oD | Directory to write enumeration results to (optional) | subfinder -oD ~/outputs |
| -oI | Write output in Host,IP format | subfinder -oI |
| -oJ | Write output in JSON lines Format | subfinder -oJ |
| -r | Comma-separated list of resolvers to use | subfinder -r 1.1.1.1,1.0.0.1 |
| -rL | Text file containing list of resolvers to use | subfinder -rL resolvers.txt
| -silent | Show only subdomains in output | subfinder -silent |
| -sources | Comma separated list of sources to use | subfinder -sources shodan,censys |
| -t | Number of concurrent goroutines for resolving (default 10) | subfinder -t 100 |
| -timeout | Seconds to wait before timing out (default 30) | subfinder -timeout 30 |
| -v | 	Show Verbose output | subfinder -v |
| -version | Show current program version | subfinder -version |


# Installation Instructions

### From Binary

The installation is easy. You can download the pre-built binaries for different platforms from the [releases](https://github.com/projectdiscovery/subfinder/releases/) page. Extract them using tar, move it to your `$PATH` and you're ready to go.

```bash
> tar -xzvf subfinder-linux-amd64.tar.gz
> mv subfinder /usr/local/local/bin/
> subfinder -h
```

### From Source

subfinder requires go1.13+ to install successfully. Run the following command to get the repo -

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/cmd/subfinder
```

### From Github

```bash
git clone https://github.com/projectdiscovery/subfinder.git
cd subfinder/cmd/subfinder
go build .
mv subfinder /usr/local/bin/
subfinder -h
```

### Upgrading
If you wish to upgrade the package you can use:

```bash
GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/cmd/subfinder
```

## Post Installation Instructions

Subfinder will work after using the installation instructions however to configure Subfinder to work with certain services, you will need to have setup API keys. The following services do not work without an API key:

- [Virustotal](https://www.virustotal.com)
- [Passivetotal](http://passivetotal.org)
- [SecurityTrails](http://securitytrails.com)
- [Censys](https://censys.io)
- [Binaryedge](https://binaryedge.io)
- [Shodan](https://shodan.io)
- [URLScan](https://urlscan.io)
- [Chaos](https://chaos.projectdiscovery.io)
- [Spyse](https://spyse.com)
- [DnsDB](https://api.dnsdb.info)
- [Zoomeye](https://www.zoomeye.org)
- [Github](https://github.com)
- [Intelx](https://intelx.io)

Theses values are stored in the `$HOME/.config/subfinder/config.yaml` file which will be created when you run the tool for the first time. The configuration file uses the YAML format. Multiple API keys can be specified for each of these services from which one of them will be used for enumeration.

For sources that require multiple keys, namely `Censys`, `Passivetotal`, they can be added by separating them via a colon (:).

An example config file -

```yaml
resolvers:
  - 1.1.1.1
  - 1.0.0.1
sources:
  - binaryedge
  - bufferover
  - censys
  - passivetotal
  - sitedossier
binaryedge:
  - 0bf8919b-aab9-42e4-9574-d3b639324597
  - ac244e2f-b635-4581-878a-33f4e79a2c13
censys:
  - ac244e2f-b635-4581-878a-33f4e79a2c13:dd510d6e-1b6e-4655-83f6-f347b363def9
certspotter: []
passivetotal:
  - sample-email@user.com:sample_password
securitytrails: []
shodan:
  - AAAAClP1bJJSRMEYJazgwhJKrggRwKA
github:
  - d23a554bbc1aabb208c9acfbd2dd41ce7fc9db39
  - asdsd54bbc1aabb208c9acfbd2dd41ce7fc9db39
```

# Running Subfinder

To run the tool on a target, just use the following command.
```bash
> subfinder -d freelancer.com
```

This will run the tool against freelancer.com. There are a number of configuration options that you can pass along with this command. The verbose switch (-v) can be used to display verbose information.

```bash
[CERTSPOTTER] www.fi.freelancer.com
[DNSDUMPSTER] hosting.freelancer.com
[DNSDUMPSTER] support.freelancer.com
[DNSDUMPSTER] accounts.freelancer.com
[DNSDUMPSTER] phabricator.freelancer.com
[DNSDUMPSTER] cdn1.freelancer.com
[DNSDUMPSTER] t1.freelancer.com
[DNSDUMPSTER] wdc.t1.freelancer.com
[DNSDUMPSTER] dal.t1.freelancer.com
```

The `-silent` switch can be used to show only subdomains found without any other info.


The `-o` command can be used to specify an output file.

```bash
> subfinder -d freelancer.com -o output.txt
```

To run the tool on a list of domains, `-dL` option can be used. This requires a directory to write the output files. Subdomains for each domain from the list are written in a text file in the directory specified by the `-oD` flag with their name being the domain name.

```bash
> cat domains.txt
hackerone.com
google.com

> subfinder -dL domains.txt -oD ~/path/to/output
> ls ~/path/to/output

hackerone.com.txt
google.com.txt
```

If you want to save results to a single file while using a domain list, specify the `-o` flag with the name of the output file.


```bash
> cat domains.txt
hackerone.com
google.com

> subfinder -dL domains.txt -o ~/path/to/output.txt
> ls ~/path/to/

output.txt
```

If you want upload your data to chaos dataset, you can use `-cd` flag with your scan, chaos will resolve all the input and add valid subdomains to public dataset, which you can access on the go using [chaos-client](https://github.com/projectdiscovery/chaos-client)

```bash
> subfinder -d hackerone.com -cd

root@b0x:~# subfinder -d hackerone.com -cd

www.hackerone.com
api.hackerone.com
go.hackerone.com
hackerone.com
staging.hackerone.com
[INF] Input processed successfully and subdomains with valid records will be updated to chaos dataset.
```

You can also get output in json format using `-oJ` switch. This switch saves the output in the JSON lines format.

If you use the JSON format, or the `Host:IP` format, then it becomes mandatory for you to use the **-nW** format as resolving is essential for these output format. By default, resolving the found subdomains is disabled.

```bash
> subfinder -d hackerone.com -o output.json -oJ -nW
> cat output.json

{"host":"www.hackerone.com","ip":"104.16.99.52"}
{"host":"mta-sts.hackerone.com","ip":"185.199.108.153"}
{"host":"hackerone.com","ip":"104.16.100.52"}
{"host":"mta-sts.managed.hackerone.com","ip":"185.199.110.153"}
```

You can specify custom resolvers too.
```bash
> subfinder -d freelancer.com -o result.txt -nW -v -r 8.8.8.8,1.1.1.1
> subfinder -d freelancer.com -o result.txt -nW -v -rL resolvers.txt
```

**The new highlight of this release is the addition of stdin/stdout features.** Now, domains can be piped to subfinder and enumeration can be ran on them. For example -

```bash
> echo hackerone.com | subfinder -v
> cat targets.txt | subfinder -v
```

The subdomains discovered can be piped to other tools too. For example, you can pipe the subdomains discovered by subfinder to httpx [httpx](https://github.com/projectdiscovery/httpx) which will then find running http servers on the host.

```bash
> echo hackerone.com | subfinder -silent | httpx -silent

http://hackerone.com
http://www.hackerone.com
http://docs.hackerone.com
http://api.hackerone.com
https://docs.hackerone.com
http://mta-sts.managed.hackerone.com
```

## Running in a Docker Container

You can use the official dockerhub image at [subfinder](https://hub.docker.com/r/projectdiscovery/subfinder). Simply run -

```bash
> docker pull projectdiscovery/subfinder
```

The above command will pull the latest tagged release from the dockerhub repository.

If you want to build the container yourself manually, git clone the repo, then build and run the following commands

- Clone the repo using `git clone https://github.com/projectdiscovery/subfinder.git`
- Build your docker container
```bash
docker build -t projectdiscovery/subfinder .
```

- After building the container using either way, run the following -
```bash
docker run -it projectdiscovery/subfinder
```
> The above command is the same as running `-h`

If you are using docker, you need to first create your directory structure holding subfinder configuration file. After modifying the default config.yaml file, you can run:

```bash
> mkdir -p $HOME/.config/subfinder
> cp config.yaml $HOME/.config/subfinder/config.yaml
> nano $HOME/.config/subfinder/config.yaml
```

After that, you can pass it as a volume using the following sample command.
```bash
> docker run -v $HOME/.config/subfinder:/root/.config/subfinder -it projectdiscovery/subfinder -d freelancer.com
```

For example, this runs the tool against uber.com and output the results to your host file system:
```bash
docker run -v $HOME/.config/subfinder:/root/.config/subfinder -it projectdiscovery/subfinder -d uber.com > uber.com.txt
```

# License

subfinder is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/subfinder/blob/master/THANKS.md)** file for more details.

Read the disclaimer for usage at [DISCLAIMER.md](https://github.com/projectdiscovery/subfinder/blob/master/DISCLAIMER.md) and [contact us](mailto:contact@projectdiscovery.io) for any API removal.
