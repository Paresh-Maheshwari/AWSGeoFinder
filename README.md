# AWS GeoFinder

A lightweight Go tool that identifies AWS region and geolocation data for IP addresses. Quickly matches IPs against official AWS ranges, providing region, location, and service information with colorized output and efficient caching for improved performance.

## Features

- Identifies AWS region for any IP address (both IPv4 and IPv6)
- Provides geolocation data (country, region, city) 
- Fast CIDR range matching
- Colorized output for better readability
- Caching of AWS IP range data for improved performance
- Multiple output formats (text and JSON)
- Batch processing of multiple IPs
- Selective data source options (AWS IP ranges, geolocation, or both)

## Installation

### Option 1: Install directly with Go

```bash
go install github.com/Paresh-Maheshwari/awsgeofinder@latest
```

After installation, you can run the tool from anywhere using:

```bash
awsgeofinder <ip_address>
```

### Option 2: Build from source

```bash
# Clone the repository
git clone https://github.com/Paresh-Maheshwari/awsgeofinder.git
cd awsgeofinder

# Build the binary
go build -o awsgeofinder

# Run the tool
./awsgeofinder <ip_address>
```

## Usage

```
DESCRIPTION:
  A tool to find AWS region and geolocation information for IP addresses.
  Uses official AWS IP ranges and geolocation data.

USAGE:
  awsgeofinder [-o text|json] [-batch] [-help] [aws|geo] <ip_address>

OPTIONS:
  -o        Output format: 'text' (default) or 'json'
  -batch    Process multiple IPs from stdin, one per line
  -help     Show this help information

DATA SOURCES:
  aws       Show only AWS IP range information
  geo       Show only geolocation information
  both      Show both AWS and geolocation information (default)
```

## Examples

Basic usage:
```bash
awsgeofinder 52.90.255.182
```

JSON output:
```bash
awsgeofinder -o json 52.90.255.182
```

### IPv6 Support Example

```bash
awsgeofinder 2600:1f14:802:7300::1
```



Only AWS IP range data:
```bash
awsgeofinder aws 52.90.255.182
```

Only geolocation data:
```bash
awsgeofinder geo 52.90.255.182
```

Pipe input:
```bash
echo "52.90.255.182" | awsgeofinder
```

Process multiple IPs:
```bash
cat ips.txt | awsgeofinder -batch
```

Process multiple IPs with JSON output:
```bash
cat ips.txt | awsgeofinder -batch -o json
```

Process multiple IPs with specific data source:
```bash
cat ips.txt | awsgeofinder -batch aws
```

## Data Sources

This tool uses two official AWS data sources:

1. **AWS IP Ranges JSON**: https://ip-ranges.amazonaws.com/ip-ranges.json
   - Contains all AWS IP ranges with their associated regions and services
   - Updated by AWS whenever new IP ranges are added or removed
   - Used to identify which AWS region an IP belongs to
   - [Official AWS Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html#aws-ip-download)

2. **AWS Geo IP Feed CSV**: https://ip-ranges.amazonaws.com/geo-ip-feed.csv
   - Contains geolocation information for AWS IP ranges
   - Includes country, region, and city information
   - Used to provide additional location context for AWS IPs
   - [Official AWS Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html#aws-ip-geo-ip-feed)

Both files are automatically downloaded when you run the tool and cached for 1 hour to improve performance.

## Local Caching

The tool implements in-memory caching of the downloaded data files:

- Data is cached for 1 hour to reduce network requests
- No manual setup required - caching happens automatically
- Improves performance for repeated lookups

For persistent caching across sessions, the tool stores data in memory during runtime. Future versions may implement file-based caching.

## Automation

You can integrate this tool into your automation workflows:

### Shell Scripts

```bash
# Example: Check if an IP is in a specific AWS region
region=$(awsgeofinder -o json 52.90.255.182 | jq -r '.matches[0].Region')
if [ "$region" == "us-east-1" ]; then
  echo "IP is in US East (N. Virginia)"
fi
```

### CI/CD Pipelines

```yaml
# Example GitHub Actions workflow
steps:
  - name: Install AWS GeoFinder
    run: go install github.com/Paresh-Maheshwari/awsgeofinder@latest
    
  - name: Check IP Region
    run: awsgeofinder ${{ env.TARGET_IP }}
```

### Monitoring Systems

```bash
# Example Nagios/Icinga check
check_aws_region() {
  output=$(awsgeofinder -o json $1)
  region=$(echo "$output" | jq -r '.matches[0].Region')
  if [ "$region" == "$2" ]; then
    echo "OK - IP $1 is in expected region $2"
    exit 0
  else
    echo "CRITICAL - IP $1 is not in expected region $2"
    exit 2
  fi
}

check_aws_region "3.5.140.2" "ap-northeast-2"
```

### Security Automation

```bash
# Example: Block traffic from specific AWS regions
for ip in $(cat suspicious_ips.txt); do
  output=$(awsgeofinder -o json $ip)
  is_aws=$(echo "$output" | jq -r '.is_aws')
  if [ "$is_aws" == "true" ]; then
    region=$(echo "$output" | jq -r '.matches[0].Region')
    if [ "$region" == "cn-north-1" ] || [ "$region" == "cn-northwest-1" ]; then
      echo "Blocking IP from China AWS region: $ip"
      # Add your blocking command here
    fi
  fi
  
  # Example: Block traffic from specific countries using geolocation data
  country=$(echo "$output" | jq -r '.geo_matches[0].Country')
  if [ "$country" == "RU" ] || [ "$country" == "KP" ]; then
    echo "Blocking IP from restricted country: $ip ($country)"
    # Add your blocking command here
  fi
}
```

## Performance Optimizations

This tool includes several optimizations for speed and efficiency:

1. **Precomputed CIDR Networks**: Parses CIDR ranges once and stores them for faster IP matching
2. **Data Caching**: Caches downloaded AWS IP data for 1 hour to reduce network requests
3. **Concurrent Downloads**: Downloads JSON and CSV files in parallel
4. **HTTP Optimizations**: Uses shorter timeouts and fewer retries for faster response
5. **Execution Time Tracking**: Shows how long the search took to complete
6. **Memory Efficiency**: Uses string splitting instead of CSV parsing for better performance
7. **Selective Data Source**: Only downloads the data files needed for the requested data source

Typical execution time: 1.5-2.5 seconds for first run, faster for subsequent runs with cached data.

## Requirements

- Go 1.16 or higher

## Contributing

Contributions are welcome! If you'd like to improve this tool:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit your changes (`git commit -m 'Add some amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

Please feel free to submit issues, feature requests, or improvements.

## Author

- **Paresh Maheshwari** - [Paresh-Maheshwari](https://github.com/Paresh-Maheshwari)

## License

MIT
