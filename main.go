package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI color codes
const (
	colorRed     = "\033[0;31m"
	colorGreen   = "\033[0;32m"
	colorYellow  = "\033[0;33m"
	colorBlue    = "\033[0;36m"  // Changed from 34 (blue) to 36 (cyan/teal)
	colorMagenta = "\033[0;35m"
	colorCyan    = "\033[0;36m"
	colorBold    = "\033[1m"
	colorNC      = "\033[0m" // No Color
)

// AWS IP ranges JSON structure
type AWSIPRanges struct {
	Prefixes     []Prefix  `json:"prefixes"`
	IPv6Prefixes []Prefix6 `json:"ipv6_prefixes"`
}

type Prefix struct {
	IPPrefix           string `json:"ip_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

type Prefix6 struct {
	IPv6Prefix         string `json:"ipv6_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

// Match structure to store unique matches
type Match struct {
	CIDR               string   `json:"CIDR"`
	Region             string   `json:"Region"`
	NetworkBorderGroup string   `json:"NetworkBorderGroup"`
	Services           []string `json:"Services"`
}

// GeoMatch structure to store geolocation information
type GeoMatch struct {
	CIDR    string `json:"CIDR"`
	Country string `json:"Country"`
	Region  string `json:"Region"`
	City    string `json:"City"`
}

// Result structure for JSON output
type Result struct {
	IPAddress     string     `json:"ip_address"`
	IsAWS         bool       `json:"is_aws"`
	Matches       []*Match   `json:"matches,omitempty"`
	GeoMatches    []*GeoMatch `json:"geo_matches,omitempty"`
	ExecutionTime float64    `json:"execution_time_seconds"`
}

// Cache structure to store downloaded data
type Cache struct {
	jsonData []byte
	csvData  []byte
	expiry   time.Time
}

var (
	// Global cache with mutex for thread safety
	cacheMutex sync.RWMutex
	dataCache  = make(map[string]*Cache)
	// Cache expiration time (1 hours for better performance)
	cacheExpiration = 1 * time.Hour
)

// Function to check if an IP is in a CIDR range
func ipInCIDR(ip net.IP, ipnet *net.IPNet) bool {
	return ipnet.Contains(ip)
}

// Function to download a file from URL with timeout and retries
func downloadFile(url string) ([]byte, error) {
	// Check cache first
	cacheMutex.RLock()
	if cache, ok := dataCache[url]; ok && time.Now().Before(cache.expiry) {
		data := cache.jsonData
		if strings.HasSuffix(url, ".csv") {
			data = cache.csvData
		}
		cacheMutex.RUnlock()
		return data, nil
	}
	cacheMutex.RUnlock()

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second, // Reduced timeout for faster response
	}

	// Try up to 2 times - reduced for faster execution
	var resp *http.Response
	var err error
	for retries := 0; retries < 2; retries++ {
		resp, err = client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Duration(retries+1) * 300 * time.Millisecond) // Reduced wait time
	}

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	// Read response body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Update cache
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	
	cache := &Cache{
		expiry: time.Now().Add(cacheExpiration),
	}
	if strings.HasSuffix(url, ".json") {
		cache.jsonData = data
	} else {
		cache.csvData = data
	}
	dataCache[url] = cache

	return data, nil
}

// Precompute CIDR networks for faster matching
func precomputeCIDRs(prefixes []Prefix) map[string]*net.IPNet {
	result := make(map[string]*net.IPNet, len(prefixes))
	for _, prefix := range prefixes {
		_, ipnet, err := net.ParseCIDR(prefix.IPPrefix)
		if err == nil {
			result[prefix.IPPrefix] = ipnet
		}
	}
	return result
}

// Function to handle error output in both text and JSON formats
func handleError(err error, message string, outputFormat string, result Result, startTime time.Time) {
	if outputFormat == "json" {
		result.ExecutionTime = time.Since(startTime).Seconds()
		jsonOutput, _ := json.Marshal(result)
		fmt.Println(string(jsonOutput))
	} else {
		fmt.Printf("%s%sError:%s %s: %v\n", colorRed, colorBold, colorNC, message, err)
	}
	os.Exit(1)
}

// Function to process CSV data and find geolocation matches
func processGeoData(csvData []byte, ip net.IP, outputFormat string, result *Result) bool {
	lines := strings.Split(string(csvData), "\n")
	geoFound := false

	// Precompute CIDR networks for CSV data
	geoCIDRNetworks := make(map[string]*net.IPNet)
	
	// Build an index of CIDR ranges for faster lookup
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 1 {
			continue
		}

		geoCIDR := strings.TrimSpace(fields[0])
		_, ipnet, err := net.ParseCIDR(geoCIDR)
		if err == nil {
			geoCIDRNetworks[geoCIDR] = ipnet
		}
	}

	// Check for matches using the precomputed networks
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		geoCIDR := strings.TrimSpace(fields[0])
		if ipnet, ok := geoCIDRNetworks[geoCIDR]; ok && ipInCIDR(ip, ipnet) {
			geoService := ""
			geoRegion := ""
			geoNetworkBorderGroup := ""

			if len(fields) > 1 {
				geoService = strings.TrimSpace(fields[1])
			}
			if len(fields) > 2 {
				geoRegion = strings.TrimSpace(fields[2])
			}
			if len(fields) > 3 {
				geoNetworkBorderGroup = strings.TrimSpace(fields[3])
			}

			geoMatch := &GeoMatch{
				CIDR:    geoCIDR,
				Country: geoService,
				Region:  geoRegion,
				City:    geoNetworkBorderGroup,
			}
			result.GeoMatches = append(result.GeoMatches, geoMatch)

			if outputFormat == "text" {
				fmt.Printf("%s%s✓ Geolocation information found:%s\n", colorGreen, colorBold, colorNC)
				fmt.Printf("%s╔════════════════════════════════════════════════════════════╗%s\n", colorCyan, colorNC)
				fmt.Printf("%s║%s %sCIDR Range:%s %s%s%s\n", colorCyan, colorNC, colorBold, colorNC, colorYellow, geoCIDR, colorNC)
				fmt.Printf("%s║%s %sCountry:%s %s%s%s\n", colorCyan, colorNC, colorBold, colorNC, colorYellow, geoService, colorNC)
				fmt.Printf("%s║%s %sRegion:%s %s%s%s\n", colorCyan, colorNC, colorBold, colorNC, colorYellow, geoRegion, colorNC)
				fmt.Printf("%s║%s %sCity:%s %s%s%s\n", colorCyan, colorNC, colorBold, colorNC, colorYellow, geoNetworkBorderGroup, colorNC)
				fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n", colorCyan, colorNC)
			}
			geoFound = true
		}
	}

	return geoFound
}

// Function to show help information
func showHelp() {
	fmt.Printf("%s%s╔════════════════════════════════════════════════════════════╗%s\n", colorCyan, colorBold, colorNC)
	fmt.Printf("%s%s║                AWS IP REGION & GEO FINDER                  ║%s\n", colorCyan, colorBold, colorNC)
	fmt.Printf("%s%s╚════════════════════════════════════════════════════════════╝%s\n", colorCyan, colorBold, colorNC)
	
	fmt.Printf("\n%s%sDESCRIPTION:%s\n", colorGreen, colorBold, colorNC)
	fmt.Printf("  A tool to find AWS region and geolocation information for IP addresses.\n")
	fmt.Printf("  Uses official AWS IP ranges and geolocation data.\n\n")
	
	fmt.Printf("%s%sUSAGE:%s\n", colorGreen, colorBold, colorNC)
	fmt.Printf("  %s [-o text|json] [-batch] [-help] [aws|geo] <ip_address>\n\n", os.Args[0])
	
	fmt.Printf("%s%sOPTIONS:%s\n", colorGreen, colorBold, colorNC)
	fmt.Printf("  %s-o%s        Output format: 'text' (default) or 'json'\n", colorYellow, colorNC)
	fmt.Printf("  %s-batch%s    Process multiple IPs from stdin, one per line\n", colorYellow, colorNC)
	fmt.Printf("  %s-help%s     Show this help information\n\n", colorYellow, colorNC)
	
	fmt.Printf("%s%sDATA SOURCES:%s\n", colorGreen, colorBold, colorNC)
	fmt.Printf("  %saws%s       Show only AWS IP range information\n", colorYellow, colorNC)
	fmt.Printf("  %sgeo%s       Show only geolocation information\n", colorYellow, colorNC)
	fmt.Printf("  %sboth%s      Show both AWS and geolocation information (default)\n\n", colorYellow, colorNC)
	
	fmt.Printf("%s%sEXAMPLES:%s\n", colorGreen, colorBold, colorNC)
	fmt.Printf("  %s%s # Basic usage%s\n", colorMagenta, os.Args[0]+" 52.90.255.182", colorNC)
	fmt.Printf("  %s%s # JSON output%s\n", colorMagenta, os.Args[0]+" -o json 52.90.255.182", colorNC)
	fmt.Printf("  %s%s # Only AWS IP range data%s\n", colorMagenta, os.Args[0]+" aws 52.90.255.182", colorNC)
	fmt.Printf("  %s%s # Only geolocation data%s\n", colorMagenta, os.Args[0]+" geo 52.90.255.182", colorNC)
	fmt.Printf("  %s%s # Pipe input%s\n", colorMagenta, "echo \"52.90.255.182\" | "+os.Args[0], colorNC)
	fmt.Printf("  %s%s # Process multiple IPs%s\n", colorMagenta, "cat ips.txt | "+os.Args[0]+" -batch", colorNC)
	fmt.Printf("  %s%s # Process multiple IPs with JSON output%s\n", colorMagenta, "cat ips.txt | "+os.Args[0]+" -batch -o json", colorNC)
	fmt.Printf("  %s%s # Process multiple IPs with specific data source%s\n", colorMagenta, "cat ips.txt | "+os.Args[0]+" -batch aws", colorNC)
	
	fmt.Printf("\n%s%sDATA SOURCES:%s\n", colorGreen, colorBold, colorNC)
	fmt.Printf("  AWS IP Ranges: https://ip-ranges.amazonaws.com/ip-ranges.json\n")
	fmt.Printf("  AWS Geo IP Feed: https://ip-ranges.amazonaws.com/geo-ip-feed.csv\n\n")
}

// Function to process a single IP address
func processIP(ipToCheck string, outputFormat string, dataSource string) int {
	startTime := time.Now()
	
	// Initialize result structure for JSON output
	result := Result{
		IPAddress: ipToCheck,
		IsAWS:     false,
		Matches:   []*Match{},
		GeoMatches: []*GeoMatch{},
	}

	// Validate IP address
	ip := net.ParseIP(ipToCheck)
	if ip == nil {
		if outputFormat == "json" {
			result.ExecutionTime = time.Since(startTime).Seconds()
			jsonOutput, _ := json.Marshal(result)
			fmt.Println(string(jsonOutput))
		} else {
			fmt.Printf("%s%sError:%s Invalid IP address format\n", colorRed, colorBold, colorNC)
		}
		return 1
	}

	if outputFormat == "text" {
		fmt.Printf("%s%s╔════════════════════════════════════════════════════════════╗%s\n", colorCyan, colorBold, colorNC)
		fmt.Printf("%s%s║                AWS IP REGION & GEO FINDER                  ║%s\n", colorCyan, colorBold, colorNC)
		fmt.Printf("%s%s╚════════════════════════════════════════════════════════════╝%s\n", colorCyan, colorBold, colorNC)
		fmt.Printf("%sSearching for region and geolocation of IP:%s %s%s%s\n", colorBlue, colorNC, colorBold, ipToCheck, colorNC)
	}

	// URLs for AWS IP ranges
	jsonURL := "https://ip-ranges.amazonaws.com/ip-ranges.json"
	csvURL := "https://ip-ranges.amazonaws.com/geo-ip-feed.csv"

	// Download files based on data source
	var wg sync.WaitGroup
	var jsonData, csvData []byte
	var jsonErr, csvErr error

	if dataSource == "both" || dataSource == "aws" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jsonData, jsonErr = downloadFile(jsonURL)
		}()
	}
	
	if dataSource == "both" || dataSource == "geo" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			csvData, csvErr = downloadFile(csvURL)
		}()
	}

	wg.Wait()

	// Handle download errors
	if (dataSource == "both" || dataSource == "aws") && jsonErr != nil {
		handleError(jsonErr, "Failed to download JSON file", outputFormat, result, startTime)
		return 1
	}
	if (dataSource == "both" || dataSource == "geo") && csvErr != nil {
		handleError(csvErr, "Failed to download CSV file", outputFormat, result, startTime)
		return 1
	}

	if outputFormat == "text" {
		if dataSource == "both" || dataSource == "aws" {
			fmt.Printf("%sSearching through AWS IP ranges...%s\n", colorBlue, colorNC)
		}
	}

	// Parse JSON data and check for AWS IP matches if using AWS data source
	found := false
	matches := make(map[string]*Match)
	
	if dataSource == "both" || dataSource == "aws" {
		var awsIPRanges AWSIPRanges
		if err := json.Unmarshal(jsonData, &awsIPRanges); err != nil {
			handleError(err, "Failed to parse JSON", outputFormat, result, startTime)
			return 1
		}

		// Precompute CIDR networks for faster matching
		cidrNetworks := precomputeCIDRs(awsIPRanges.Prefixes)

		// Check each prefix
		for _, prefix := range awsIPRanges.Prefixes {
			if ipnet, ok := cidrNetworks[prefix.IPPrefix]; ok && ipInCIDR(ip, ipnet) {
				matchKey := fmt.Sprintf("%s|%s|%s", prefix.IPPrefix, prefix.Region, prefix.NetworkBorderGroup)
				if match, exists := matches[matchKey]; exists {
					match.Services = append(match.Services, prefix.Service)
				} else {
					match := &Match{
						CIDR:               prefix.IPPrefix,
						Region:             prefix.Region,
						NetworkBorderGroup: prefix.NetworkBorderGroup,
						Services:           []string{prefix.Service},
					}
					matches[matchKey] = match
					result.Matches = append(result.Matches, match)
				}
				found = true
				result.IsAWS = true
			}
		}

		// Check each IPv6 prefix
		for _, prefix := range awsIPRanges.IPv6Prefixes {
			_, ipnet, err := net.ParseCIDR(prefix.IPv6Prefix)
			if err == nil && ipInCIDR(ip, ipnet) {
				matchKey := fmt.Sprintf("%s|%s|%s", prefix.IPv6Prefix, prefix.Region, prefix.NetworkBorderGroup)
				if match, exists := matches[matchKey]; exists {
					match.Services = append(match.Services, prefix.Service)
				} else {
					match := &Match{
						CIDR:               prefix.IPv6Prefix,
						Region:             prefix.Region,
						NetworkBorderGroup: prefix.NetworkBorderGroup,
						Services:           []string{prefix.Service},
					}
					matches[matchKey] = match
					result.Matches = append(result.Matches, match)
				}
				found = true
				result.IsAWS = true
			}
		}

		// Display all matches from ip-ranges.json
		if found {
			if outputFormat == "text" {
				fmt.Printf("\n%s%s✓ Found matches for IP %s in ip-ranges.json:%s\n", colorGreen, colorBold, ipToCheck, colorNC)
				fmt.Printf("%s╔════════════════════════════════════════════════════════════╗%s\n", colorMagenta, colorNC)

				for _, match := range matches {
					fmt.Printf("%s║%s %sRegion:%s %s%s%s\n", colorMagenta, colorNC, colorBold, colorNC, colorYellow, match.Region, colorNC)
					fmt.Printf("%s║%s %sNetwork Border Group:%s %s%s%s\n", colorMagenta, colorNC, colorBold, colorNC, colorYellow, match.NetworkBorderGroup, colorNC)
					fmt.Printf("%s║%s %sCIDR Range:%s %s%s%s\n", colorMagenta, colorNC, colorBold, colorNC, colorYellow, match.CIDR, colorNC)
					fmt.Printf("%s║%s %sServices:%s %s%s%s\n", colorMagenta, colorNC, colorBold, colorNC, colorYellow, strings.Join(match.Services, ", "), colorNC)
					fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n", colorMagenta, colorNC)
				}
			}
		} else if outputFormat == "text" && dataSource == "aws" {
			fmt.Printf("%s%s✗ IP %s was not found in any AWS region%s\n", colorRed, colorBold, ipToCheck, colorNC)
		}
	}

	// Check for geolocation information if using geo data source
	geoFound := false
	if dataSource == "both" || dataSource == "geo" {
		if outputFormat == "text" && dataSource == "both" && found {
			// Only show this message if we're showing both data sources and AWS data was found
			fmt.Printf("\n%sChecking geolocation information in geo-ip-feed.csv...%s\n", colorBlue, colorNC)
		}
		
		// Process CSV data and find geolocation matches
		geoFound = processGeoData(csvData, ip, outputFormat, &result)

		if !geoFound && outputFormat == "text" && dataSource == "geo" {
			fmt.Printf("%s%s⚠ No geolocation information found for this IP in geo-ip-feed.csv%s\n", colorYellow, colorBold, colorNC)
		}
	}

	// Handle case where no data was found in either source
	if !found && !geoFound && outputFormat == "text" && dataSource == "both" {
		fmt.Printf("%s%s✗ IP %s was not found in any AWS region or geolocation data%s\n", colorRed, colorBold, ipToCheck, colorNC)
	}

	result.ExecutionTime = time.Since(startTime).Seconds()

	if outputFormat == "json" {
		// Output JSON result
		jsonOutput, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			handleError(err, "Failed to generate JSON output", outputFormat, result, startTime)
			return 1
		}
		fmt.Println(string(jsonOutput))
	} else if found || geoFound {
		fmt.Printf("\n%s%s✓ Search completed successfully in %.2f seconds!%s\n", colorGreen, colorBold, result.ExecutionTime, colorNC)
		return 0
	} else {
		return 1
	}
	
	return 0
}

// Function to process multiple IPs from stdin in batch mode
func processBatchInput(outputFormat string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		ipToCheck := strings.TrimSpace(scanner.Text())
		if ipToCheck == "" {
			continue
		}
		processIP(ipToCheck, outputFormat, "both") // Use both data sources in batch mode
	}
	
	if err := scanner.Err(); err != nil {
		fmt.Printf("%s%sError:%s Failed to read input: %v\n", colorRed, colorBold, colorNC, err)
		os.Exit(1)
	}
}

func main() {
	// Define command-line flags
	outputFormat := flag.String("o", "text", "Output format: text or json")
	batchMode := flag.Bool("batch", false, "Process multiple IPs from stdin, one per line")
	helpFlag := flag.Bool("help", false, "Show help information")
	flag.Parse()

	// Validate output format
	if *outputFormat != "text" && *outputFormat != "json" {
		fmt.Printf("%s%sError:%s Invalid output format. Use 'text' or 'json'\n", colorRed, colorBold, colorNC)
		os.Exit(1)
	}

	// Show help if requested
	if *helpFlag {
		showHelp()
		return
	}

	// Check if we're in batch mode
	if *batchMode {
		processBatchInput(*outputFormat)
		return
	}

	// Check command line arguments
	args := flag.Args()
	var ipToCheck string
	var dataSource string = "both" // Default to both data sources
	
	// Check if first argument is a data source specifier
	if len(args) > 0 && (args[0] == "aws" || args[0] == "geo") {
		dataSource = args[0]
		args = args[1:] // Remove the data source from args
	}
	
	// Check if we're receiving input from a pipe
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		// Reading from pipe
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			ipToCheck = strings.TrimSpace(scanner.Text())
		} else {
			fmt.Printf("%s%sError:%s No input received from pipe\n", colorRed, colorBold, colorNC)
			os.Exit(1)
		}
	} else if len(args) == 1 {
		// Reading from command line argument
		ipToCheck = args[0]
	} else {
		showHelp()
		os.Exit(1)
	}
	
	// Process the single IP
	exitCode := processIP(ipToCheck, *outputFormat, dataSource)
	os.Exit(exitCode)
}
