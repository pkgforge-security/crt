### ℹ️ About
This is a fork of [cemulus/crt](https://github.com/cemulus/crt) with some major changes.

### 🖳 Installation
Use [soar](https://github.com/pkgforge/soar) & Run:
```bash
soar add 'crt#github.com.pkgforge-security.crt'
```

### 🧰 Usage
```mathematica
❯ crt --help

Usage: crt [options...] <domain name>

NOTE:
  → Options must come before Input (Unless using -i)
  → Each connection is opened only for 5 Mins, with 3 Retries
  → NRD Indicator needs at least 3 Results to be Accurate
  → To pipe to other Tools, use -q 2>/dev/null | ${TOOL}
  → For Bulk mode, Always use -o to prevent Data Loss

Options:
  -e        Exclude Expired Certificates [Default: False]
  -s        Enumerate Subdomains [Default: False]
  -c <int>  Number of concurrent lookups for Bulk Mode [Default: 5]
  -d <int>  Delay between requests in milliseconds [Default: 500]
  -i <path> Input file containing domain names (one per line) for bulk lookup
  -l <int>  Limit the number of results (more results take more time) [Default: 10]
  -o <path> Output file path [Default: STDOUT]
  -r <int>  Number of retries for failed requests [Default: 3]
  -csv      Turn results to CSV
  -json     Turn results to JSON
  -jsonl    Turn results to JSONL (JSON Lines)
  -q        Quiet mode (Hide progress messages, only show results) [Bulk Mode Only]

Examples:
  crt "example.com"
  crt -s -e "example.com"
  crt -json -o logs.json "example.com"
  crt -l 15 -csv -o logs.csv "example.com"
  crt -jsonl -q -s "example.com" 2>/dev/null | jq -r ".subdomain"
  crt -i domains.txt -s -e -json -o results.json
  crt -i domains.txt -c 100 -d 10 -jsonl
```