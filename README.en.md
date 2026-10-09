# Passive Domain Inventory — Python

Documentation française : [README.md](README.md). Script français :
[`domain_inventory.py`](domain_inventory.py).

`domain_inventory_en.py` collects public domain, contact, DNS, subdomain, IP,
and network-operator information. It can optionally run a bounded TCP connect
Nmap scan against discovered IP addresses.

Keep `output_merge.py`, `global_output.py`, and `virustotal_enrichment.py` in the same directory as
`domain_inventory.py` and `domain_inventory_en.py`. Both main scripts import
these modules for historical merging, the global view, and VirusTotal support.

The French and English scripts provide the same collection features and accept
the same command-line options. The English version keeps the established CSV
filenames and column names so existing integrations remain compatible, while
its source comments, docstrings, command-line help, warnings, and progress
messages are in English.

## Requirements

- Python 3.10 or newer;
- PyYAML 6.x;
- outbound HTTPS access to the enabled services;
- outbound DNS access;
- Nmap only when `--nmap` is enabled.

The passive sources include `rdap.org`, `crt.sh`, `dns.google`, and `ipwho.is`.
DNSDumpster, who.is, WhoisXML API, and VirusTotal are optional and require
personal API keys.

## Installation on Windows

In PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
```

Install Nmap for Windows only if you intend to use `--nmap`. Ensure `nmap.exe`
is in `PATH`, or provide its location through `--nmap-path`.

## Installation on Debian/Linux

Using Debian packages:

```bash
sudo apt update
sudo apt install python3 python3-yaml ca-certificates
```

Install Nmap only when needed:

```bash
sudo apt install nmap
```

Alternatively, use an isolated Python environment:

```bash
sudo apt install python3 python3-venv ca-certificates
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Do not use `sudo pip install`. Use Debian's `python3-yaml` package or a virtual
environment. Official package references: [python3-yaml](https://packages.debian.org/stable/python/python3-yaml)
and [nmap](https://packages.debian.org/stable/nmap).

## Basic usage

Put one domain per line in `domains.txt`.

Windows:

```powershell
python .\domain_inventory_en.py --input .\domains.txt --output .\results
```

Debian/Linux:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --output ./results
```

For one or more domains without an input file:

```bash
python3 ./domain_inventory_en.py --domain example.com --domain example.org
```

Useful options include `--workers 12`, `--delay 0.35`, and `--retries 3`.

## Overwrite or merge results

The default behavior still replaces all ten source CSV files:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --output ./results --output-mode overwrite
```

To retain history in the same directory, enable deduplicated merging:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --output ./results --output-mode merge
```

On Windows, use `python .\domain_inventory_en.py` with the same options.

Merge mode:

- loads existing CSV files;
- deduplicates each dataset with a stable natural key;
- retains old rows that are not observed during the new run;
- updates non-empty fields with the new observation;
- never erases a known value with a new empty value;
- counts a key at most once per execution, even if the current collection
  contains duplicate rows;
- atomically replaces CSV files and `resume.json` after writing temporary files.

Three columns are appended to every source CSV in both modes:

- `PremiereObservation`: UTC timestamp of the first observation;
- `DerniereObservation`: UTC timestamp of the latest run that found the item;
- `NombreObservations`: number of executions in which the item was observed.

When a legacy CSV has none of these columns, its filesystem modification time
is used as the initial historical timestamp during the first merge. This is a
migration approximation, not proof of the actual first-discovery time.

`resume.json` represents the cumulative CSV state after merging and includes an
`output_mode` field. It is replaced rather than concatenated.

## YAML configuration

Copy the provided example before editing it.

Windows:

```powershell
Copy-Item .\config.example.yaml .\config.yaml
python .\domain_inventory_en.py --config .\config.yaml --input .\domains.txt
```

Debian/Linux:

```bash
cp ./config.example.yaml ./config.yaml
chmod 600 ./config.yaml
python3 ./domain_inventory_en.py --config ./config.yaml --input ./domains.txt
```

The default path is `config.yaml` in the current directory. The file is
optional; built-in values remain active when it does not exist. Use `--config`
to select another file.

The YAML configuration controls:

- the HTTP user agent;
- the domain validation regular expression;
- the CDN/reverse-proxy detection expression;
- common subdomain prefixes;
- default DKIM selectors;
- default Nmap ports;
- DNSDumpster, who.is, WhoisXML API, and VirusTotal API keys.

Minimal API-key section:

```yaml
api_keys:
  dnsdumpster: "your_dnsdumpster_key"
  whois: "your_whois_key"
  whoisxmlapi: "your_whoisxmlapi_key"
  virustotal: "your_virustotal_key"
```

`config.yaml` and `config.local.yaml` are ignored by Git. Never put real keys in
the tracked `config.example.yaml`. On Linux, protect a local secret-bearing file
with `chmod 600 config.yaml`.

Configuration precedence is:

1. command-line option, when an equivalent option exists;
2. environment variable for API keys;
3. YAML value;
4. built-in default.

## API keys through environment variables

Environment variables override YAML keys.

Windows PowerShell:

```powershell
$env:DNSDUMPSTER_API_KEY = "your_dnsdumpster_key"
$env:WHOIS_API_KEY = "your_whois_key"
$env:WHOISXMLAPI_API_KEY = "your_whoisxmlapi_key"
$env:VIRUSTOTAL_API_KEY = "your_virustotal_key"
python .\domain_inventory_en.py --input .\domains.txt --output .\results
Remove-Item Env:DNSDUMPSTER_API_KEY
Remove-Item Env:WHOIS_API_KEY
Remove-Item Env:WHOISXMLAPI_API_KEY
Remove-Item Env:VIRUSTOTAL_API_KEY
```

Bash/Linux:

```bash
export DNSDUMPSTER_API_KEY="your_dnsdumpster_key"
export WHOIS_API_KEY="your_whois_key"
export WHOISXMLAPI_API_KEY="your_whoisxmlapi_key"
export VIRUSTOTAL_API_KEY="your_virustotal_key"
python3 ./domain_inventory_en.py --input ./domains.txt --output ./results
unset DNSDUMPSTER_API_KEY WHOIS_API_KEY WHOISXMLAPI_API_KEY VIRUSTOTAL_API_KEY
```

Keys are not written to CSV files, the JSON summary, or normal program logs.

## Quota tracking

The DNSDumpster Free User defaults are 50 requests per day with no more than
one request every two seconds. The who.is Free defaults are 500 credits per UTC
calendar month and one request per second. WhoisXML API uses a non-calendar DRS
balance; the Subdomains Lookup price documented by the provider is 10 credits
per requested page.

Persistent counters are stored at:

- Windows: `%LOCALAPPDATA%\DomainInventory\dnsdumpster-usage.json` and
  `%LOCALAPPDATA%\DomainInventory\whois-usage.json`; WhoisXML API additionally
  uses `%LOCALAPPDATA%\DomainInventory\whoisxmlapi-usage.json`, and VirusTotal
  uses `%LOCALAPPDATA%\DomainInventory\virustotal-usage.json` when enabled;
- Linux: `~/.domain-inventory/dnsdumpster-usage.json` and
  `~/.domain-inventory/whois-usage.json`; WhoisXML API additionally uses
  `~/.domain-inventory/whoisxmlapi-usage.json`, and VirusTotal uses
  `~/.domain-inventory/virustotal-usage.json` when enabled.

Counter files contain no API key or domain. Provide dashboard usage when calls
were made from another tool:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --dnsdumpster-today-count 17
python3 ./domain_inventory_en.py --input ./domains.txt --whois-month-count 125
```

The higher of the supplied and persistent counters is retained. API rate-limit
headers take precedence when available.

## who.is modes

`--whois-source` accepts:

- `whois` — `/v1/whois/{domain}`, one credit per domain;
- `rdap` — `/v1/rdap/{domain}`, one credit per domain;
- `both` — WHOIS followed by RDAP, up to two credits per domain.

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --whois-source both
```

The script checks the remaining local quota before every endpoint call.

## Optional WhoisXML API subdomain discovery

Subdomains Lookup remains disabled unless `--whoisxml-subdomains` is supplied.
It complements `crt.sh`, DNSDumpster, and the common-name tests; every accepted
name then follows the normal DNS-resolution pipeline.

```bash
export WHOISXMLAPI_API_KEY="your_whoisxmlapi_key"
python3 ./domain_inventory_en.py --input ./domains.txt \
  --output ./results --whoisxml-subdomains
```

The script first queries the [official balance endpoint](https://subdomains.whoisxmlapi.com/api/documentation/account-balance-information).
If the DRS balance cannot be parsed, it uses the persistent
`whoisxmlapi-usage.json` counter and the `--whoisxml-drs-credit-limit` and
`--whoisxml-credits-used` fallback options. The provider documents
[500 free DRS credits](https://subdomains.whoisxmlapi.com/api/documentation/making-requests)
and a [10-credit cost per request](https://subdomains.whoisxmlapi.com/api/pricing).

One page contains at most 10,000 results. The default is therefore one page per
domain. `--whoisxml-max-pages 2` allows the next `searchAfter` page when enough
credits remain. The request rate stays under the provider's
[30 requests/second limit](https://subdomains.whoisxmlapi.com/api/documentation/making-requests).
Paid page requests are never automatically retried.

Provider `firstSeen` and `lastSeen` values are preserved in
`whoisxml-subdomains.csv`. They do not replace `DerniereDecouverte` in
`inventaire-global.csv`, which remains the time this script actually rediscovered
and resolved the DNS observation.

## Optional VirusTotal discovery and reputation analysis

`--virustotal` enables API v3. For each root domain, the script requests its
report and then the `subdomains` relationship. That relationship returns direct
subdomains and their domain objects; it is
[not recursive](https://docs.virustotal.com/reference/domain-object-subdomains).

```bash
export VIRUSTOTAL_API_KEY="your_virustotal_key"
python3 ./domain_inventory_en.py --input ./domains.txt \
  --output ./results --virustotal --virustotal-plan public
```

The `public` profile enforces at least 15 seconds between requests and a local
500-request UTC daily ceiling, matching the official
[4 requests/minute and 500 requests/day limits](https://docs.virustotal.com/reference/public-vs-premium-api).
VirusTotal also states that the public API must not be used in commercial
products or certain non-contributive business workflows. Confirm that your use
is permitted. Select `--virustotal-plan premium` only with a corresponding
license and configure the interval and ceiling according to that contract.

The default requests one page of 10 direct subdomains. Pagination is bounded by
`--virustotal-max-pages` and `--virustotal-page-size`. Returned objects populate
`virustotal.csv` and add VirusTotal to `SourceSousDomaine` before DNS resolution.

The normal path consumes two requests per known root domain: one report and one
first subdomain page. The public 500-request ceiling therefore covers at most
250 root domains per day before pagination or extra reports. A 400-domain batch
must be split across days on the public API or run under an appropriate license.

To query individual reports for names found through other sources:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --virustotal \
  --virustotal-analyze-discovered --virustotal-max-extra-reports 20
```

Every individual report consumes one request. The persistent
`virustotal-usage.json` counter resets on a UTC date change, while
`--virustotal-today-count` accounts for calls made elsewhere. An error or HTTP
429 disables this source for the remaining batch without stopping other sources.

The verdict summarizes the documented `last_analysis_stats` fields on
[Domain objects](https://docs.virustotal.com/reference/domains-object). It is
not proof of maliciousness: malicious/suspicious engine counts, community
reputation, categories, and analysis time remain available for human review.
Configure the malicious signal threshold with
`--virustotal-malicious-threshold`.

## DNS and email checks

For every domain, Google Public DNS over HTTPS is queried for:

- MX;
- TXT and SPF;
- CNAME;
- AAAA;
- DMARC at `_dmarc.<domain>`;
- DKIM using common configurable selectors.

DKIM selectors cannot be discovered generically through DNS. Override the
defaults by repeating `--dkim-selector`:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt \
  --dkim-selector selector1 \
  --dkim-selector selector2 \
  --dkim-selector custom-selector
```

The common names `ftp`, `mail`, `www`, `webmail`, `ns1`, and `ns2` are resolved
by default. A random nonexistent name is also resolved to detect wildcard DNS.

## Optional bounded Nmap scan

Nmap is disabled by default. Enable it only for IP addresses you own or are
explicitly authorized to audit:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --output ./results --nmap
```

The profile is intentionally bounded:

- TCP connect (`-sT`) only;
- 18 common TCP ports by default;
- `-T3` timing and a 50 ms scan delay;
- one retry at most;
- 30-second host timeout;
- no version detection, OS detection, NSE scripts, or UDP;
- public IP addresses only by default;
- 256 IP addresses at most per run.

Options:

```bash
# Explicit list, limited to 100 ports
python3 ./domain_inventory_en.py --input ./domains.txt --nmap --nmap-ports 22,80,443

# Explicit Linux executable
python3 ./domain_inventory_en.py --input ./domains.txt --nmap --nmap-path /usr/bin/nmap

# Lower target limit
python3 ./domain_inventory_en.py --input ./domains.txt --nmap --nmap-max-ips 50

# Include private/non-global IPs only when authorized
python3 ./domain_inventory_en.py --input ./domains.txt --nmap --nmap-include-private
```

The `-sT` profile normally requires no root privileges. Do not run the complete
script with `sudo`; doing so changes file ownership and unnecessarily exposes
API keys to a privileged process. TCP connections can still be logged by the
target. "Low impact" does not mean invisible.

## Output files

- `domaines.csv`: registrar, dates, statuses, name servers, and contact summary;
- `contacts-rdap.csv`: public RDAP entities and roles;
- `contacts-whois.csv`: normalized who.is WHOIS/RDAP contacts;
- `dnsdumpster.csv`: DNSDumpster hosts, IPs, PTRs, ASNs, and countries;
- `whoisxml-subdomains.csv`: WhoisXML API subdomains with provider first-seen
  and last-seen UTC timestamps. The CSV is created even when the source is
  disabled so the output schema remains stable;
- `virustotal.csv`: VirusTotal reports for queried root domains and subdomains,
  including engine counts, community reputation, categories, analysis time, and
  a synthetic verdict. Unknown domains are retained with
  `StatutRequete=NonTrouve` and `Verdict=NonEvalue`;
- `enregistrements-dns.csv`: consolidated DNS and email checks;
- `sous-domaines-dns.csv`: discovered/tested names and A/AAAA resolution;
- `adresses-ip.csv`: ASN, operator, country, and probable hosting attribution;
- `nmap.csv`: bounded TCP port results when Nmap is enabled;
- `inventaire-global.csv`: denormalized view combining root domain, registrar,
  who.is administrative contacts, subdomains, IP attribution, and Nmap ports.
  Its `DerniereDecouverte` column is copied from `DerniereObservation` on the
  corresponding `sous-domaines-dns.csv` row. Each row represents a domain,
  subdomain, type, IP, and port combination;
- `resume.json`: execution counts, quota state, and methodological warnings.

CSV files use semicolons and UTF-8 with BOM for spreadsheet compatibility. The
English script intentionally preserves the established French filenames and
column identifiers so both language versions can feed the same downstream
processing.

`inventaire-global.csv` contains: `DomaineRacine`, `Registrar`,
`ContactAdministratif`, `SousDomaine`, `Type`, `Resolu`,
`SourceSousDomaine`, `DerniereDecouverte`, `AdresseIP`, `Organisation`, `ISP`,
`HebergeurProbable`, `CDNouProxy`, `SourceAttribution`, `HoteEtat`, `Port`, and
`Etat`. Contacts carrying the `admin` or `administrative` role are deduplicated
and concatenated as `Name | Organization | Email | Phone`.
`DerniereDecouverte` is an ISO 8601 UTC timestamp. In `merge` mode, it changes
only when the same DNS observation is found again; it therefore remains
unchanged for a historical observation missing from the current run.
For a legacy CSV without observation columns, it follows the migration rule
described above: the file modification time becomes the initial historical
timestamp and is therefore a documented approximation.

When VirusTotal is enabled, `inventaire-global.csv` also contains
`VirusTotalVerdict`, `VirusTotalMalicieux`, `VirusTotalSuspect`,
`VirusTotalReputation`, and `VirusTotalDerniereAnalyse`. These columns join on
`DomaineRacine + SousDomaine` and remain empty when no report was requested or
found.

## Generate a complete HTML report

The companion `generate_report.py` script converts an existing output directory
into a self-contained HTML report. It makes no network request and never alters
the source CSV or JSON files.

Windows:

```powershell
python .\generate_report.py `
  --input-dir .\results `
  --output .\results\report.html `
  --language en
```

Debian/Linux:

```bash
python3 ./generate_report.py \
  --input-dir ./results \
  --output ./results/report.html \
  --language en
```

When `--output` is omitted, the report is written to
`<input-dir>/report.html`. Available languages are `fr` and `en`.

The report includes:

- execution overview cards;
- availability status for every expected file;
- every field from `resume.json`;
- every row from all eleven CSV files;
- the number of observed open Nmap ports;
- methodological and hosting-attribution warnings.

The HTML embeds its own style, works offline, and includes print styling. CSV
and JSON values are HTML-escaped before insertion. Missing files are reported
without preventing the remaining sections from being generated.

## Privacy and limitations

Domains and discovered names are transmitted to enabled public services.
Without optional keys, these services are `rdap.org`, `crt.sh`, `dns.google`,
and `ipwho.is`. Enabling DNSDumpster, who.is, or WhoisXML API also sends domains
to those providers. Enabling `--virustotal` sends domains to VirusTotal. The
script only reads existing reports; it does not submit files or URLs for a new
analysis.

RDAP contact data may be redacted. Certificate Transparency logs are not an
exhaustive subdomain inventory. An IP may belong to a CDN, reverse proxy, or
cloud platform, so probable hosting identifies the apparent IP operator rather
than necessarily identifying the origin infrastructure.
