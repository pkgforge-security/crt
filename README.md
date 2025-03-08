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
Check whether a domain has a rate limit enabled

Usage:
  crt [flags]

Flags:
  -h, --help                 help for crt
  -i, --ignore-code-change   Continue after the code changing
  -X, --method string        HTTP method to use (default "GET")
  -o, --output string        Output file for logs
  -c, --requests-count int   Number of requests to send (default 1000)
  -t, --threads int          Number of threads to use (default 10)
  -u, --url string           URL to send requests to
```