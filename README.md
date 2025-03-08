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
  → Options must come before Input
  → Each connection is opened only for 5 mins, with 3 Retries
  → NRD Indicator needs at least 3 Results to be Accurate

Options:
  -e        Exclude Expired Certificates
  -s        Enumerate Subdomains
  -c <int>  Number of concurrent lookups for Bulk Mode [Default: 5]
  -d <int>  Delay between requests in milliseconds [Default: 500)
  -i <path> Input file containing domain names (one per line) for bulk lookup
  -l <int>  Limit the number of results (more results take more time) [Default: 10)
  -o <path> Output file path [Default: STDOUT]
  -r <int>  Number of retries for failed requests [Default: 3)
  -csv      Turn results to CSV
  -json     Turn results to JSON
  -jsonl    Turn results to JSONL (JSON Lines)
  -q        Quiet mode (Hide progress messages, only show results)

Examples:
  crt example.com
  crt -s -e example.com
  crt -json -o logs.json example.com
  crt -l 15 -csv -o logs.csv example.com
  crt -i domains.txt -s -e -json -o results.json
  crt -i domains.txt -c 3 -d 0 -jsonl

```