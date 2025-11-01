# Pure Python URL Extractor v5.0

A powerful, standalone Python tool for extracting all URLs and file extensions from a target website without relying on external tools like `gau` or `urlfinder`.

**Author: ArkhAngelLifeJiggy**

## Features

- **🎯 Comprehensive URL Discovery**: Extracts URLs from multiple sources:
  - Wayback Machine (historical URLs)
  - Common Crawl (archived URLs)
  - Live website crawling
  - JavaScript file analysis

- **📊 Advanced URL Categorization**:
  - **Known URLs**: Publicly available URLs from archives
  - **Hidden URLs**: URLs found in JavaScript files and comments
  - **Internal URLs**: URLs within the same domain
  - **External URLs**: URLs pointing to other domains

- **🔍 Categorized File Extension Analysis**:
  - **JavaScript**: `.js`, `.jsx`, `.ts`, `.coffee`, `.vue`
  - **HTML**: `.html`, `.htm`, `.xhtml`, `.xml`
  - **CSS**: `.css`, `.scss`, `.sass`, `.less`
  - **Images**: `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.svg`, `.ico`
  - **Documents**: `.pdf`, `.doc`, `.docx`, `.txt`, `.md`, `.rtf`
  - **Archives**: `.zip`, `.rar`, `.tar`, `.gz`, `.7z`, `.bz2`
  - **Media**: `.mp4`, `.mp3`, `.avi`, `.mov`, `.wmv`, `.flv`
  - **Other**: All remaining extensions

- **🛡️ Advanced WAF Bypass & Anti-Detection**:
  - User agent rotation (5+ realistic browsers)
  - IP spoofing with X-Forwarded-For headers
  - Smart delaying mechanisms with randomization
  - Custom proxy support (HTTP/HTTPS)
  - Cache control and connection header randomization
  - Request retry mechanism with exponential backoff

- **✅ Advanced Validation & Filtering**:
  - False positive detection and removal (`data:`, `javascript:`, `mailto:`)
  - MD5-based duplicate prevention with hash collision detection
  - URL normalization and validation with regex patterns
  - Domain-based filtering with subdomain support
  - Extension-based filtering (include/exclude specific file types)
  - Pattern matching with regex include/exclude rules

- **📝 Comprehensive Logging System**:
  - Automatic timestamped log file generation
  - INFO, WARNING, ERROR level logging with context
  - Detailed operation tracking with performance metrics
  - Custom log file path support
  - Structured logging for debugging and analysis

- **🎨 Beautiful Interactive Interface**:
  - Colorful terminal output with 8-color support
  - Real-time progress indicators and status updates
  - Professional ASCII banner with author credits
  - Categorized results display with statistics
  - Quiet mode and stats-only output options

- **📊 Multiple Output Formats**:
  - **JSON**: Structured data with categorized results and metadata
  - **CSV**: Spreadsheet-compatible format with URL, source, type, extension columns
  - **XML**: Machine-readable format with proper schema
  - **Statistics Only**: Summary output for automation
  - **Custom Formatting**: Flexible output options

- **⚙️ Advanced Configuration Options** (20+ parameters):
  - **Crawling**: `max-pages`, `max-depth`, `concurrency`, `timeout`
  - **Security**: `waf-bypass`, `user-agent`, `proxy`, `delay`, `retries`
  - **Filtering**: `exclude-extensions`, `include-only`, `exclude-pattern`
  - **Output**: `csv`, `xml`, `quiet`, `stats-only`, `save-html`
  - **Debugging**: `verbose`, `log-file`, `no-color`

- **⚡ Pure Python Implementation**: No external dependencies on Go tools

- **🔧 Configurable Parameters**: Fine-grained control over all aspects

- **📦 PyPI Package**: Ready for `pip install url-extractor`

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python url_extractor.py https://example.com
```

### Advanced Usage with WAF Bypass
```bash
python url_extractor.py https://example.com \
  --output results.json \
  --verbose \
  --waf-bypass \
  --delay 2.0 \
  --max-pages 200 \
  --max-depth 4 \
  --threads 20
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target_url` | Target URL to extract URLs from (required) | - |
| `-o, --output` | Output file for results (JSON/CSV/XML) | - |
| `-v, --verbose` | Enable verbose output | False |
| `-p, --max-pages` | Maximum pages to crawl | 100 |
| `-d, --max-depth` | Maximum crawl depth | 3 |
| `-t, --threads` | Number of threads for concurrent processing | 10 |
| `--delay` | Delay between requests in seconds | 1.0 |
| `--waf-bypass` | Enable WAF bypass techniques | False |
| `--user-agent` | Custom user agent string | Random |
| `--proxy` | HTTP proxy (http://proxy:port) | - |
| `--timeout` | Request timeout in seconds | 30 |
| `--max-js-files` | Maximum JS files to analyze | 20 |
| `--concurrency` | Number of concurrent requests | 5 |
| `--retries` | Number of retries for failed requests | 3 |
| `--exclude-extensions` | Comma-separated extensions to exclude | - |
| `--include-only` | Include only URLs containing this string | - |
| `--exclude-pattern` | Exclude URLs matching regex pattern | - |
| `--save-html` | Save HTML responses for analysis | False |
| `--quiet` | Suppress all output except results | False |
| `--stats-only` | Show only statistics, no URLs | False |
| `--csv` | Output in CSV format | False |
| `--xml` | Output in XML format | False |
| `--log-file` | Custom log file path | Auto-generated |
| `--no-color` | Disable colored output | False |

## Output

The tool provides a comprehensive summary including:

- Total number of unique URLs found
- URLs categorized by type (known, hidden, internal, external)
- File extensions organized by category
- Top extensions with counts
- Optional JSON export with all URLs and metadata

### JSON Output Format
```json
{
  "target_url": "https://example.com",
  "domain": "example.com",
  "timestamp": "2025-09-17T13:00:00.000000",
  "total_urls": 150,
  "categorized_urls": {
    "known": ["https://example.com/page1", ...],
    "hidden": ["https://example.com/api/secret", ...],
    "internal": ["https://example.com/about", ...],
    "external": ["https://cdn.example.com/script.js", ...]
  },
  "categorized_extensions": {
    "javascript": {"js": 25, "jsx": 5},
    "html": {"html": 10, "xml": 2},
    "css": {"css": 15, "scss": 3},
    "images": {"png": 45, "jpg": 30},
    "documents": {"pdf": 5, "txt": 8},
    "archives": {"zip": 2, "gz": 1},
    "media": {"mp4": 3, "mp3": 7},
    "other": {"json": 12, "xml": 8}
  },
  "all_urls": ["https://example.com/", ...],
  "statistics": {
    "total_known": 120,
    "total_hidden": 15,
    "total_internal": 135,
    "total_external": 15,
    "total_extensions": 89
  }
}
```

## How It Works

1. **Wayback Machine**: Queries the Internet Archive for historical URLs
2. **Common Crawl**: Fetches URLs from the Common Crawl index
3. **Website Crawling**: Performs breadth-first crawling of the target site
4. **JavaScript Analysis**: Parses JS files to extract embedded URLs
5. **URL Normalization**: Converts relative URLs to absolute URLs
6. **Validation & Filtering**: Removes false positives and duplicates
7. **Categorization**: Classifies URLs by type and source
8. **Extension Analysis**: Groups file extensions by category

## Examples

### Extract URLs from a website with WAF bypass
```bash
python url_extractor.py https://bugcrowd.com --waf-bypass --delay 1.5 -v
```

### Deep crawl with custom logging
```bash
python url_extractor.py https://example.com \
  -v -p 500 -d 5 \
  -o results.json \
  --log-file custom_scan.log
```

### Quick scan with minimal resources
```bash
python url_extractor.py https://example.com \
  -p 50 -d 2 -t 5 \
  --no-color
```

### Full security testing mode
```bash
python url_extractor.py https://target.com \
  --waf-bypass \
  --delay 3.0 \
  --max-pages 1000 \
  --max-depth 5 \
  --threads 30 \
  --verbose \
  --output security_scan.json
```

### Advanced filtering and output options
```bash
# Filter specific file types and use multiple output formats
python url_extractor.py https://site.com \
  --exclude-extensions pdf,doc,zip,rar \
  --include-only api \
  --csv --xml --json \
  --proxy http://127.0.0.1:8080 \
  --user-agent "Custom Security Scanner v1.0"

# Quiet mode for automation with custom logging
python url_extractor.py https://target.com \
  --quiet \
  --stats-only \
  --log-file /var/log/url_scan.log \
  --exclude-pattern "\.(jpg|png|gif)$" \
  --concurrency 10 \
  --timeout 60
```

### PyPI Installation (Future)
```bash
pip install url-extractor
url-extractor https://example.com --waf-bypass
```

## Dependencies

- `requests>=2.25.0`: HTTP client for web requests
- `beautifulsoup4>=4.9.0`: HTML parsing
- `lxml>=4.6.0`: XML/HTML parser (optional, for better performance)

## Logging

The tool automatically creates detailed log files with timestamps:

```
2025-09-17 14:07:08,349 - INFO - Starting URL Extractor v5.0 by ArkhAngelLifeJiggy
2025-09-17 14:07:08,350 - INFO - Target: https://bugcrowd.com
2025-09-17 14:08:32,058 - INFO - Wayback Machine: 201482 valid URLs found
2025-09-17 14:08:32,974 - INFO - Common Crawl: 0 valid URLs found
2025-09-17 14:08:35,831 - INFO - Live Crawling: 140 valid URLs found
```

## WAF Bypass Features

- **User Agent Rotation**: Cycles through 5+ realistic browser signatures
- **IP Spoofing**: Randomized X-Forwarded-For and X-Real-IP headers
- **Smart Delaying**: Configurable delays with randomization to avoid detection
- **Header Randomization**: Varies cache-control, connection, and other headers
- **Request Pattern Variation**: Mimics human browsing behavior

## Validation & Filtering

- **False Positive Detection**: Automatically filters out:
  - `data:` URLs
  - `javascript:` URLs
  - `mailto:` links
  - `tel:` links
  - Fragment-only URLs (#)
  - Chrome/Safari internal URLs

- **Duplicate Prevention**: MD5 hash-based deduplication ensures no repeated URLs

- **URL Validation**: Ensures all URLs have valid schemes and netloc

- **Domain Filtering**: Respects same-domain boundaries for internal/external classification

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Disclaimer

This tool is for educational and research purposes only. Always respect website terms of service and robots.txt files when crawling websites. Use responsibly and ethically.