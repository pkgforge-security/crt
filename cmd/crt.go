package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"github.com/pkgforge-security/crt/repository"
	"github.com/pkgforge-security/crt/result"
)

var (
	initTime time.Time
	concurrent   = flag.Int("c", 5, "")
	csvOut       = flag.Bool("csv", false, "")
	expired      = flag.Bool("e", false, "")
	filename     = flag.String("o", "", "")
	inputFile    = flag.String("i", "", "")
	jsonOut      = flag.Bool("json", false, "")
	jsonlOut     = flag.Bool("jsonl", false, "")
	limit        = flag.Int("l", 10, "")
	quietMode    = flag.Bool("q", false, "")
	requestDelay = flag.Int("d", 500, "")
	retryCount   = flag.Int("r", 3, "")
	subdomain    = flag.Bool("s", false, "")
)

var usage = `Usage: crt [options...] <domain name>

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
`

// Shared buffers for collecting results
var (
	// Mutex to protect shared resources
	fileMutex  sync.Mutex
	resultsMux sync.Mutex
	
	// Buffers for collecting results
	jsonResults  []json.RawMessage
	jsonlResults []json.RawMessage
	tableResults bytes.Buffer
	csvResults   bytes.Buffer
	
	//Realpath for Output
	absFilename string

	// Flag to track if we're shutting down due to interrupt
	shuttingDown bool
	shutdownMux  sync.Mutex
)

// logf prints messages only if quiet mode is disabled
func logf(format string, args ...interface{}) {
	if !*quietMode {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

func Execute() {
	initTime = time.Now()
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	
	// Realpath to file
    if *filename != "" {
        absPath, err := filepath.Abs(*filename)
        if err != nil {
            absFilename = *filename // Fallback to original
        } else {
            absFilename = absPath
        }

		// Extract directory path and create missing directories
		dir := filepath.Dir(absFilename)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("❌ Failed to create directories: %v", err)
		}

    // Check if file is not empty
    if fileInfo, err := os.Stat(absFilename); err == nil && fileInfo.Size() > 0 {
    	logf("⚠️ Warning: File %s is not empty. Clearing contents.\n", absFilename)
    	if err := os.Truncate(absFilename, 0); err != nil {
    		log.Fatalf("❌ Failed to clear file contents: %v", err)
    	}
		}

    logf("💾 Output will be saved to: %s\n", absFilename)
    } else {
        absFilename = ""
    }

	// Set up signal handling for graceful shutdown
	setupSignalHandling()
	
	// Validate incompatible output formats
	if (*jsonOut && *csvOut) || (*jsonOut && *jsonlOut) || (*csvOut && *jsonlOut) {
		fmt.Fprintln(os.Stderr, "❌ Error: Only one output format can be specified")
		flag.Usage()
		os.Exit(1)
	}
	
	// If input file is provided, perform bulk lookup
	if *inputFile != "" {
		performBulkLookup()
		return
	}
	
	// Single domain lookup
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	
	domain := flag.Args()[0]
	if domain == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Create a repository connection for single domain
	repo, err := repository.New()
	if err != nil {
		log.Fatalf("❌ Failed to create repository: %v", err)
	}
	defer repo.Close()

	if err := lookupDomainWithRepo(repo, domain); err != nil {
		log.Fatal(err)
	}
	
	// Output final results for single domain
	outputResults()
}

// setupSignalHandling sets up handlers for interrupt signals
func setupSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		logf("\n⚠️ Interrupt received. Saving results and shutting down...\n")
		
		shutdownMux.Lock()
		shuttingDown = true
		shutdownMux.Unlock()
		
		// Save any collected results
		outputResults()
		
		os.Exit(130) // Standard exit code for interrupt
	}()
}

// isShuttingDown checks if we're in shutdown mode
func isShuttingDown() bool {
	shutdownMux.Lock()
	defer shutdownMux.Unlock()
	return shuttingDown
}

func lookupDomainWithRepo(repo *repository.Repository, domain string) error {
	// Safety check to prevent index errors with some certificates 
	if domain == "" {
		return fmt.Errorf("❌ Empty Domain Name")
	}
	
	// Don't start new lookups if we're shutting down
	if isShuttingDown() {
		return fmt.Errorf("shutdown in progress")
	}
	
	for attempt := 0; attempt <= *retryCount; attempt++ {
		// Check for shutdown between retry attempts
		if attempt > 0 && isShuttingDown() {
			return fmt.Errorf("interrupted")
		}
		
		// Add delay between retries
		if attempt > 0 {
			time.Sleep(time.Duration(*requestDelay) * time.Millisecond)
			//logf("\nⓘ Retry %d for %s\n", attempt, domain)
		}

		var res result.Printer
		var err error

		if *subdomain {
			res, err = repo.GetSubdomains(domain, *expired, *limit)
		} else {
			res, err = repo.GetCertLogs(domain, *expired, *limit)
		}

		if err != nil {
			if attempt < *retryCount {
				logf("\n❌ Error looking up %s: %v. Retrying (%d/%d)...\n", domain, err, attempt+1, *retryCount)
				continue
			}
			return fmt.Errorf("❌ Lookup failed for %s after %d/%d attempts: %w", domain, *retryCount+1, *retryCount+1, err)
		}
		
		if res.Size() == 0 {
			if !*jsonOut && !*jsonlOut {
				logf("ⓘ Found no results for %s.\n", domain)
			}
			return nil
		}
		
		// Process the results based on the output format
		processResults(res, domain)
		
		return nil // Success
	}
	
	return fmt.Errorf("❌ Unexpected Error - Max Retries Exceeded")
}

func processResults(res result.Printer, domain string) {
	if *jsonOut || *jsonlOut {
		// Get JSON data
		jsonData, err := res.JSON()
		if err != nil {
			logf("❌ Failed to format results as JSON for %s: %v\n", domain, err)
			return
		}
		
		resultsMux.Lock()
		if *jsonOut {
			// Parse the original array and add each item to our results
			var items []json.RawMessage
			if err := json.Unmarshal(jsonData, &items); err == nil {
				jsonResults = append(jsonResults, items...)
			} else {
				logf("❌ Invalid JSON array for %s: %v\n", domain, err)
			}
		} else if *jsonlOut {
			// For JSONL format, we need to parse the array and add each item separately
			var items []json.RawMessage
			if err := json.Unmarshal(jsonData, &items); err == nil {
				for _, item := range items {
					// Use Marshal to ensure each item is compact (no newlines)
					compactJSON, err := json.Marshal(item)
					if err == nil {
						jsonlResults = append(jsonlResults, compactJSON)
					} else {
						logf("❌ Failed to marshal JSON item: %v\n", err)
					}
				}
			} else {
				logf("❌ Invalid JSON array for %s: %v\n", domain, err)
			}
		}
		resultsMux.Unlock()
		
		// Direct output to file if specified
		if *filename != "" {
			fileMutex.Lock()
			defer fileMutex.Unlock()
			
			flag := os.O_CREATE | os.O_WRONLY
			if *jsonlOut {
				flag |= os.O_APPEND // Append for JSONL
			} else {
				flag |= os.O_TRUNC // Truncate for JSON
			}
			
			file, err := os.OpenFile(*filename, flag, 0644)
			if err != nil {
				logf("❌ Failed to open output file: %v\n", err)
				return
			}
			defer file.Close()
			
			if *jsonlOut {
       // For JSONL, write each item on a new line
       var items []json.RawMessage
       if err := json.Unmarshal(jsonData, &items); err == nil {
         for _, item := range items {
           // Use Marshal to ensure each item is compact (no newlines)
           compactJSON, err := json.Marshal(item)
           if err != nil {
             logf("❌ Failed to marshal JSON item: %v\n", err)
             continue
           }
           if _, err := file.Write(compactJSON); err != nil {
             logf("❌ Failed to write to file: %v\n", err)
           }
           if _, err := file.Write([]byte("\n")); err != nil {
             logf("❌ Failed to write newline to file: %v\n", err)
           }
         }
       }
			} else if *jsonOut {
				// For JSON, we'll write a complete array at the end in outputResults
			}
		}
	} else if *csvOut {
		// CSV handling remains the same
		csvData, err := res.CSV()
		if err != nil {
			logf("❌ Failed to format results as CSV for %s: %v\n", domain, err)
			return
		}
		
		resultsMux.Lock()
		csvResults.Write(csvData)
		csvResults.WriteString("\n")
		resultsMux.Unlock()
		
		// Direct output to file if specified
		if *filename != "" {
			fileMutex.Lock()
			defer fileMutex.Unlock()
			
			file, err := os.OpenFile(*filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				logf("❌ Failed to open output file: %v\n", err)
				return
			}
			defer file.Close()
			
			if _, err := file.Write(csvData); err != nil {
				logf("❌ Failed to write to file: %v\n", err)
			}
			file.WriteString("\n")
		}
	} else {
		// Table format remains the same
		tableData := res.Table()
		
		resultsMux.Lock()
		tableResults.Write(tableData)
		tableResults.WriteString("\n\n")
		resultsMux.Unlock()
		
		// Direct output to file if specified
		if *filename != "" {
			fileMutex.Lock()
			defer fileMutex.Unlock()
			
			file, err := os.OpenFile(*filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				logf("❌ Failed to open output file: %v\n", err)
				return
			}
			defer file.Close()
			
			if _, err := file.Write(tableData); err != nil {
				logf("❌ Failed to write to file: %v\n", err)
			}
			file.WriteString("\n\n")
		}
	}
}

func outputResults() {
	// Only output to stdout if no filename is specified
	if *filename == "" {
		if *jsonOut && len(jsonResults) > 0 {
			// Create a single JSON array with all results
			combinedJSON, err := json.MarshalIndent(jsonResults, "", "  ")
			if err != nil {
				logf("❌ Failed to combine JSON results: %v\n", err)
				return
			}
			fmt.Println(string(combinedJSON))
    } else if *jsonlOut && len(jsonlResults) > 0 {
      // Output each JSON result on a separate line
      for _, result := range jsonlResults {
       fmt.Println(string(result))
      }
		} else if *csvOut && csvResults.Len() > 0 {
			fmt.Print(csvResults.String())
		} else if tableResults.Len() > 0 {
			fmt.Print(tableResults.String())
		}
	} else if *jsonOut && len(jsonResults) > 0 {
		// For JSON with filename, write the complete array at the end
		combinedJSON, err := json.MarshalIndent(jsonResults, "", "  ")
		if err != nil {
			logf("❌ Failed to combine JSON results: %v\n", err)
			return
		}
		
		// Ensure the directory exists before writing the file
		err = os.MkdirAll(filepath.Dir(*filename), 0755)
		if err != nil {
			logf("❌ Failed to create directories: %v\n", err)
			return
		}

		// Write the complete JSON array to the file
		fileMutex.Lock()
		defer fileMutex.Unlock()

		if err := os.WriteFile(*filename, combinedJSON, 0644); err != nil {
			logf("❌ Failed to write JSON to file: %v\n", err)
			return
		}
	}

	// Always log if results were saved to a file
	if *filename != "" {
		if isShuttingDown() {
			logf("✅ Saved partial results to %s before shutdown\n", absFilename)
		} else {
			logf("✅ Saved Results to %s\n", absFilename)
		}
	}

	// Log time elapsed
	elapsed := time.Since(initTime)
	fmt.Fprintf(os.Stderr, "⌚ Finished in %s\n", elapsed.Round(time.Millisecond))
}

func performBulkLookup() {
	// Check if input file exists
	file, err := os.Open(*inputFile)
	if err != nil {
		log.Fatalf("failed to open input file: %s", err)
	}
	defer file.Close()
	
	// Read domains from the file
	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			domains = append(domains, domain)
		}
	}
	
	if err := scanner.Err(); err != nil {
		log.Fatalf("❌ Error reading input file: %s", err)
	}
	
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "No domains found in input file.")
		os.Exit(1)
	}
	
	// Clear output file if it's specified and not in JSONL mode
	if *filename != "" && !*jsonlOut {
		if err := os.WriteFile(*filename, []byte{}, 0644); err != nil {
			log.Fatalf("failed to clear output file: %s", err)
		}
	}
	
	// Check for valid concurrency value
	if *concurrent < 1 {
		fmt.Fprintln(os.Stderr, "Warning: Invalid concurrency value. Setting to 1.")
		*concurrent = 1
	}

	// Create a single repository connection
	repo, err := repository.New()
	if err != nil {
		log.Fatalf("❌ Failed to create repository: %v", err)
	}
	defer repo.Close()

	// Process domains with limited concurrency
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *concurrent)
	errorChannel := make(chan error, len(domains))
	
	// Track processed domains for status updates
	var processedCount int32
	var processedMutex sync.Mutex
	totalDomains := len(domains)
	
	if !*quietMode {
		fmt.Fprintf(os.Stderr, "ℹ️ Processing %d Domains (Concurrency:%d, Delay:%dms, Retries:%d) [Limit:%d]\n", 
			len(domains), *concurrent, *requestDelay, *retryCount, *limit)
	}
	
	for _, domain := range domains {
		// Don't start new lookups if we're shutting down
		if isShuttingDown() {
			break
		}
		
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore
		go func(d string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore
			
			// Skip if we're shutting down
			if isShuttingDown() {
				return
			}
			
			// Add configured delay between requests
			time.Sleep(time.Duration(*requestDelay) * time.Millisecond)
			
			if err := lookupDomainWithRepo(repo, d); err != nil {
				// Don't report errors during shutdown
				if !isShuttingDown() {
					errorChannel <- err
					logf("❌ Error processing %s: %v\n", d, err)
				}
			}
			
			// Update progress counter
			processedMutex.Lock()
			processedCount++
			progress := processedCount
			processedMutex.Unlock()
			
			// Show progress periodically
			if !*quietMode && !isShuttingDown() && progress%10 == 0 {
				fmt.Fprintf(os.Stderr, "⏱️ Progress: %d/%d domains processed (%.1f%%)\n", 
					progress, totalDomains, float64(progress)/float64(totalDomains)*100)
			}
		}(domain)
	}
	
	wg.Wait()
	close(errorChannel)
	
	// Check if there were any errors
	errCount := 0
	for err := range errorChannel {
		if isShuttingDown() {
			// Don't report errors during shutdown
			continue
		}
		logf("❌ Error: %v\n", err)
		errCount++
	}
	
	// Output final results
	outputResults()
	
	if !*quietMode && !isShuttingDown() {
		elapsed := time.Since(initTime)
		if errCount > 0 {
			fmt.Fprintf(os.Stderr, "⚠️ Bulk lookup completed with %d errors in %s.\n", errCount, elapsed.Round(time.Millisecond))
		} else {
			fmt.Fprintf(os.Stderr, "\n✅ Bulk lookup completed successfully in %s.\n", elapsed.Round(time.Millisecond))
		}
	}
}