#!/usr/bin/env python3
"""
Pure Python URL Extractor - A powerful tool to extract all URLs and extensions from a target URL
without relying on external tools like gau or urlfinder.

Author: ArkhAngelLifeJiggy
Features:
- Extracts known, hidden, internal, and external URLs
- Identifies all file extensions with categorization
- Uses Wayback Machine, Common Crawl, and web crawling
- Parses JavaScript files for hidden URLs
- WAF bypass techniques and delaying mechanisms
- Comprehensive logging and validation
- Colorful interactive interface
"""

import argparse
import requests
import re
import json
import time
import urllib.parse
from urllib.parse import urlparse, urljoin
from collections import defaultdict, deque
from bs4 import BeautifulSoup
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os
import logging
import random
import hashlib
from datetime import datetime

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Banner
def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═════════════════════════════════════════════════════════════╗
║                     URL EXTRACTOR                           ║
║                    Pure Python Power                        ║
║                                                             ║
║  Author: ArkhAngelLifeJiggy                                 ║
║  Version: 5.0                                               ║
║  Features: URL Discovery | Extension Analysis | WAF Bypass  ║
╚═════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

# Setup logging
def setup_logging(log_file=None):
    if log_file is None:
        log_file = f"url_extractor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_file

class PureURLExtractor:
    def __init__(self, target_url: str, output_file: str = None, verbose: bool = False,
                 max_pages: int = 100, max_depth: int = 3, threads: int = 10,
                 delay: float = 1.0, waf_bypass: bool = True):
        self.target_url = target_url
        self.output_file = output_file
        self.verbose = verbose
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.threads = threads
        self.delay = delay
        self.waf_bypass = waf_bypass

        self.domain = self.extract_domain(target_url)
        self.base_url = f"{urlparse(target_url).scheme}://{self.domain}"

        # Results storage
        self.urls = set()
        self.extensions = defaultdict(int)
        self.categorized_extensions = {
            'javascript': defaultdict(int),  # .js, .jsx, .ts, .coffee
            'html': defaultdict(int),        # .html, .htm, .xhtml
            'css': defaultdict(int),         # .css, .scss, .sass, .less
            'images': defaultdict(int),      # .png, .jpg, .jpeg, .gif, .webp, .svg, .ico
            'documents': defaultdict(int),   # .pdf, .doc, .docx, .txt, .md
            'archives': defaultdict(int),    # .zip, .rar, .tar, .gz, .7z
            'media': defaultdict(int),       # .mp4, .mp3, .avi, .mov, .wmv
            'other': defaultdict(int)        # Everything else
        }
        self.categorized_urls = {
            'known': set(),      # From Wayback Machine, Common Crawl
            'hidden': set(),     # From JS files, comments, etc.
            'internal': set(),   # Same domain
            'external': set()    # Different domain
        }

        # Validation and deduplication
        self.url_hashes = set()  # For duplicate detection
        self.false_positives = set()  # Common false positive patterns

        # Crawling data
        self.visited = set()
        self.to_visit = deque()
        self.session = requests.Session()

        # WAF bypass user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]

        self.setup_session()

        # Regex patterns
        self.url_pattern = re.compile(r'https?://[^\s<>"\']+')
        self.js_url_pattern = re.compile(r'["\']([^"\']*\.js[^"\']*)["\']')
        self.relative_url_pattern = re.compile(r'(?:href|src|action|data-url)=["\']([^"\']+)["\']')

        # Initialize false positive patterns
        self.init_false_positives()

        # Setup logging
        self.logger = logging.getLogger('URLExtractor')

    def init_false_positives(self):
        """Initialize false positive patterns to filter out"""
        self.false_positives = {
            'data:', 'javascript:', 'mailto:', 'tel:', 'fax:', 'file:',
            'about:', 'chrome:', 'edge:', 'opera:', 'safari:',
            '#', 'javascript:void(0)', 'javascript:;', 'mailto:',
            'tel:', 'sms:', 'geo:', 'maps:', 'intent:'
        }

    def setup_session(self):
        """Setup session with WAF bypass headers"""
        # Rotate user agent
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # Add some randomization to avoid detection
        if self.waf_bypass:
            self.session.headers.update({
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'X-Forwarded-For': f'192.168.{random.randint(1,255)}.{random.randint(1,255)}',
                'X-Real-IP': f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}',
            })

    def rotate_user_agent(self):
        """Rotate user agent to avoid detection"""
        self.session.headers['User-Agent'] = random.choice(self.user_agents)

    def smart_delay(self):
        """Implement smart delaying to avoid rate limiting"""
        if self.waf_bypass:
            delay = self.delay + random.uniform(0.5, 2.0)
            time.sleep(delay)
        else:
            time.sleep(self.delay)

    def is_false_positive(self, url: str) -> bool:
        """Check if URL is a false positive"""
        url_lower = url.lower()
        for fp in self.false_positives:
            if url_lower.startswith(fp):
                return True
        return False

    def get_url_hash(self, url: str) -> str:
        """Generate hash for URL deduplication"""
        return hashlib.md5(url.encode()).hexdigest()

    def is_duplicate(self, url: str) -> bool:
        """Check if URL is duplicate"""
        url_hash = self.get_url_hash(url)
        if url_hash in self.url_hashes:
            return True
        self.url_hashes.add(url_hash)
        return False

    def categorize_extension(self, url: str):
        """Categorize file extension"""
        parsed = urlparse(url)
        path = parsed.path
        if '.' in path:
            ext = path.split('.')[-1].lower()
            if ext in ['js', 'jsx', 'ts', 'coffee', 'vue']:
                self.categorized_extensions['javascript'][ext] += 1
            elif ext in ['html', 'htm', 'xhtml', 'xml']:
                self.categorized_extensions['html'][ext] += 1
            elif ext in ['css', 'scss', 'sass', 'less']:
                self.categorized_extensions['css'][ext] += 1
            elif ext in ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico', 'bmp']:
                self.categorized_extensions['images'][ext] += 1
            elif ext in ['pdf', 'doc', 'docx', 'txt', 'md', 'rtf', 'odt']:
                self.categorized_extensions['documents'][ext] += 1
            elif ext in ['zip', 'rar', 'tar', 'gz', '7z', 'bz2']:
                self.categorized_extensions['archives'][ext] += 1
            elif ext in ['mp4', 'mp3', 'avi', 'mov', 'wmv', 'flv', 'wav']:
                self.categorized_extensions['media'][ext] += 1
            else:
                self.categorized_extensions['other'][ext] += 1

    def extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc

    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.domain or parsed.netloc.endswith('.' + self.domain)
        except:
            return False

    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False

    def normalize_url(self, url: str, base_url: str = None) -> str:
        """Normalize URL to absolute form"""
        if not url:
            return ""

        try:
            if url.startswith('//'):
                url = 'https:' + url
            elif url.startswith('/'):
                url = urljoin(base_url or self.base_url, url)
            elif not url.startswith(('http://', 'https://')):
                url = urljoin(base_url or self.base_url, url)

            # Remove fragments
            parsed = urlparse(url)
            url = parsed._replace(fragment='').geturl()

            return url
        except:
            return ""

    def extract_urls_from_html(self, html: str, base_url: str) -> set:
        """Extract URLs from HTML content"""
        urls = set()

        try:
            # Extract from href, src, etc.
            soup = BeautifulSoup(html, 'html.parser')

            # Links
            for link in soup.find_all('a', href=True):
                url = self.normalize_url(link['href'], base_url)
                if url and self.is_valid_url(url):
                    urls.add(url)

            # Scripts
            for script in soup.find_all('script', src=True):
                url = self.normalize_url(script['src'], base_url)
                if url and self.is_valid_url(url):
                    urls.add(url)

            # Images, CSS, etc.
            for tag in soup.find_all(['img', 'link', 'form']):
                src = tag.get('src') or tag.get('href') or tag.get('action')
                if src:
                    url = self.normalize_url(src, base_url)
                    if url and self.is_valid_url(url):
                        urls.add(url)

        except Exception as e:
            if self.verbose:
                print(f"Error parsing HTML: {e}")

        # Extract from JavaScript (even if HTML parsing failed)
        js_urls = self.extract_urls_from_js(html)
        urls.update(js_urls)

        return urls

    def extract_urls_from_js(self, content: str) -> set:
        """Extract URLs from JavaScript content"""
        urls = set()

        try:
            # Find URLs in JS strings
            for match in self.url_pattern.finditer(content):
                url = match.group(0)
                if url and self.is_valid_url(url):
                    urls.add(url)

            # Find relative URLs in JS
            for match in self.relative_url_pattern.finditer(content):
                url = self.normalize_url(match.group(1))
                if url and self.is_valid_url(url):
                    urls.add(url)

            # Find URLs in common JS patterns
            js_patterns = [
                r'["\']([^"\']*\.js[^"\']*)["\']',  # JS files
                r'["\']([^"\']*\.css[^"\']*)["\']', # CSS files
                r'["\']([^"\']*\.(png|jpg|jpeg|gif|webp|svg)[^"\']*)["\']', # Images
                r'["\']([^"\']*api[^"\']*)["\']',   # API endpoints
                r'["\']([^"\']*endpoint[^"\']*)["\']', # Endpoints
            ]

            for pattern in js_patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    url = match.group(1)
                    if url:
                        normalized_url = self.normalize_url(url)
                        if normalized_url and self.is_valid_url(normalized_url):
                            urls.add(normalized_url)

        except Exception as e:
            if self.verbose:
                print(f"Error extracting URLs from JS: {e}")

        return urls

    def fetch_wayback_urls(self) -> set:
        """Fetch URLs from Wayback Machine"""
        urls = set()
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=original&collapse=urlkey"
            response = self.session.get(wayback_url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for item in data[1:]:  # Skip header
                    if len(item) > 0:
                        url = item[0]
                        if url.startswith('http'):
                            urls.add(url)

            if self.verbose:
                print(f"Wayback Machine found {len(urls)} URLs")

        except Exception as e:
            if self.verbose:
                print(f"Error fetching Wayback URLs: {e}")

        return urls

    def fetch_common_crawl_urls(self) -> set:
        """Fetch URLs from Common Crawl"""
        urls = set()
        try:
            # Get latest index
            index_url = "https://index.commoncrawl.org/"
            response = self.session.get(index_url, timeout=10)

            if response.status_code == 200:
                # Parse for latest index
                soup = BeautifulSoup(response.text, 'html.parser')
                latest_index = None

                for link in soup.find_all('a'):
                    href = link.get('href', '')
                    if 'CC-MAIN-' in href:
                        latest_index = href
                        break

                if latest_index:
                    cdx_url = f"https://index.commoncrawl.org/{latest_index}cdx?url={self.domain}/*"
                    response = self.session.get(cdx_url, timeout=30)

                    if response.status_code == 200:
                        for line in response.text.split('\n'):
                            if line.strip():
                                parts = line.split()
                                if len(parts) > 2:
                                    url = parts[2]
                                    if url.startswith('http'):
                                        urls.add(url)

            if self.verbose:
                print(f"Common Crawl found {len(urls)} URLs")

        except Exception as e:
            if self.verbose:
                print(f"Error fetching Common Crawl URLs: {e}")

        return urls

    def crawl_website(self) -> set:
        """Crawl website to find URLs"""
        urls = set()
        self.to_visit.append((self.target_url, 0))  # (url, depth)
        self.visited.add(self.target_url)

        while self.to_visit and len(self.visited) < self.max_pages:
            current_url, depth = self.to_visit.popleft()

            if depth >= self.max_depth:
                continue

            try:
                response = self.session.get(current_url, timeout=15)
                if response.status_code != 200:
                    if self.verbose:
                        print(f"Skipping {current_url} (status: {response.status_code})")
                    continue

                page_urls = self.extract_urls_from_html(response.text, current_url)
                urls.update(page_urls)

                # Add new URLs to queue (limit to same domain for efficiency)
                for url in page_urls:
                    if (url not in self.visited and
                        self.is_same_domain(url) and
                        len(self.visited) < self.max_pages):
                        self.visited.add(url)
                        self.to_visit.append((url, depth + 1))

                if self.verbose and len(self.visited) % 10 == 0:
                    print(f"Crawled {len(self.visited)} pages, found {len(urls)} URLs")

            except requests.exceptions.Timeout:
                if self.verbose:
                    print(f"Timeout crawling {current_url}")
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"Request error crawling {current_url}: {e}")
            except Exception as e:
                if self.verbose:
                    print(f"Error crawling {current_url}: {e}")
                continue

        return urls

    def fetch_js_files(self) -> set:
        """Find and fetch JavaScript files"""
        js_urls = set()
        js_files_processed = 0
        max_js_files = min(20, len([url for url in self.urls if url.endswith('.js') or '.js?' in url]))  # Limit JS files to process

        # Find JS files from crawled pages
        for url in self.urls:
            if js_files_processed >= max_js_files:
                break

            if url.endswith('.js') or '.js?' in url:
                try:
                    # Add smart delay before JS requests
                    self.smart_delay()

                    response = self.session.get(url, timeout=8)  # Shorter timeout for JS files
                    if response.status_code == 200:
                        js_content_urls = self.extract_urls_from_js(response.text)

                        # Filter and validate JS URLs
                        valid_js_urls = set()
                        for js_url in js_content_urls:
                            if not self.is_false_positive(js_url) and not self.is_duplicate(js_url):
                                if js_url not in self.urls:
                                    valid_js_urls.add(js_url)

                        js_urls.update(valid_js_urls)

                        if self.verbose and valid_js_urls:
                            print(f"{Colors.CYAN}[+] Found {len(valid_js_urls)} URLs in {url}{Colors.END}")

                    js_files_processed += 1

                except requests.exceptions.Timeout:
                    if self.verbose:
                        print(f"{Colors.YELLOW}[!] Timeout fetching JS file {url}{Colors.END}")
                except requests.exceptions.RequestException as e:
                    if self.verbose:
                        print(f"{Colors.RED}[!] Request error fetching JS file {url}: {e}{Colors.END}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.RED}[!] Error fetching JS file {url}: {e}{Colors.END}")

        self.logger.info(f"JavaScript Analysis: Processed {js_files_processed} JS files, found {len(js_urls)} URLs")
        return js_urls

    def extract_extension(self, url: str) -> str:
        """Extract file extension from URL"""
        parsed = urlparse(url)
        path = parsed.path
        if '.' in path:
            ext = path.split('.')[-1].lower()
            # Filter out common non-file extensions
            if ext not in ['html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'cgi', 'pl', 'py', 'js', 'css', 'xml', 'json', 'txt', 'md', 'yml', 'yaml']:
                return ext
        return 'no_extension'

    def categorize_url(self, url: str, source: str) -> None:
        """Categorize URL by type"""
        # Add to source category
        if source in self.categorized_urls:
            self.categorized_urls[source].add(url)

        # Internal vs External
        if self.is_same_domain(url):
            self.categorized_urls['internal'].add(url)
        else:
            self.categorized_urls['external'].add(url)

        # Extract extension for legacy compatibility
        ext = self.extract_extension(url)
        self.extensions[ext] += 1

        # Also categorize extension in new system
        self.categorize_extension(url)

    def extract(self) -> None:
        """Main extraction process"""
        self.logger.info(f"Starting pure Python URL extraction for: {self.target_url}")
        self.logger.info(f"Domain: {self.domain}")
        print(f"{Colors.GREEN}[+] Starting extraction for: {self.target_url}{Colors.END}")
        print(f"{Colors.BLUE}[+] Domain: {self.domain}{Colors.END}")
        print(f"{Colors.YELLOW}[+] WAF Bypass: {'Enabled' if self.waf_bypass else 'Disabled'}{Colors.END}")
        print(f"{Colors.CYAN}[+] Delay: {self.delay}s{Colors.END}")
        print("-" * 60)

        # Fetch from Wayback Machine
        print(f"{Colors.MAGENTA}[+] Fetching URLs from Wayback Machine...{Colors.END}")
        wayback_urls = self.fetch_wayback_urls()
        valid_wayback = 0
        total_wayback = len(wayback_urls)

        if self.verbose:
            print(f"{Colors.BLUE}[+] Processing {total_wayback} Wayback URLs...{Colors.END}")

        for url in wayback_urls:
            is_valid = self.is_valid_url(url)
            is_fp = self.is_false_positive(url)
            is_dup = self.is_duplicate(url)
            already_exists = url in self.urls

            if is_valid and not is_fp and not is_dup and not already_exists:
                self.urls.add(url)
                self.categorize_url(url, 'known')
                valid_wayback += 1
            elif self.verbose and (is_fp or is_dup):
                print(f"{Colors.YELLOW}[!] Filtered {url[:50]}... (FP: {is_fp}, Dup: {is_dup}){Colors.END}")

        self.logger.info(f"Wayback Machine: {valid_wayback}/{total_wayback} valid URLs found")
        print(f"{Colors.GREEN}[+] Wayback Machine: {valid_wayback} valid URLs{Colors.END}")

        # Fetch from Common Crawl
        print(f"{Colors.MAGENTA}[+] Fetching URLs from Common Crawl...{Colors.END}")
        common_crawl_urls = self.fetch_common_crawl_urls()
        valid_common = 0
        for url in common_crawl_urls:
            if self.is_valid_url(url) and not self.is_false_positive(url) and not self.is_duplicate(url):
                if url not in self.urls:
                    self.urls.add(url)
                    self.categorize_url(url, 'known')
                    self.categorize_extension(url)
                    valid_common += 1
        self.logger.info(f"Common Crawl: {valid_common} valid URLs found")
        print(f"{Colors.GREEN}[+] Common Crawl: {valid_common} valid URLs{Colors.END}")

        # Crawl website
        print(f"{Colors.MAGENTA}[+] Crawling website...{Colors.END}")
        crawled_urls = self.crawl_website()
        valid_crawled = 0
        for url in crawled_urls:
            if self.is_valid_url(url) and not self.is_false_positive(url) and not self.is_duplicate(url):
                if url not in self.urls:
                    self.urls.add(url)
                    self.categorize_url(url, 'known')
                    self.categorize_extension(url)
                    valid_crawled += 1
        self.logger.info(f"Live Crawling: {valid_crawled} valid URLs found")
        print(f"{Colors.GREEN}[+] Live Crawling: {valid_crawled} valid URLs{Colors.END}")

        # Fetch JavaScript files
        print(f"{Colors.MAGENTA}[+] Analyzing JavaScript files...{Colors.END}")
        js_urls = self.fetch_js_files()
        valid_js = 0
        for url in js_urls:
            if self.is_valid_url(url) and not self.is_false_positive(url) and not self.is_duplicate(url):
                if url not in self.urls:
                    self.urls.add(url)
                    self.categorize_url(url, 'hidden')
                    self.categorize_extension(url)
                    valid_js += 1
        self.logger.info(f"JavaScript Analysis: {valid_js} valid URLs found")
        print(f"{Colors.GREEN}[+] JavaScript Analysis: {valid_js} valid URLs{Colors.END}")

        print("-" * 60)
        print(f"{Colors.BOLD}{Colors.GREEN}[+] Total unique URLs found: {len(self.urls)}{Colors.END}")
        self.logger.info(f"Total unique URLs found: {len(self.urls)}")

    def save_results(self) -> None:
        """Save results to file"""
        if not self.output_file:
            return

        results = {
            'target_url': self.target_url,
            'domain': self.domain,
            'total_urls': len(self.urls),
            'timestamp': datetime.now().isoformat(),
            'categorized_urls': {
                'known': list(self.categorized_urls['known']),
                'hidden': list(self.categorized_urls['hidden']),
                'internal': list(self.categorized_urls['internal']),
                'external': list(self.categorized_urls['external'])
            },
            'categorized_extensions': {
                category: dict(extensions)
                for category, extensions in self.categorized_extensions.items()
            },
            'all_urls': list(self.urls),
            'statistics': {
                'total_known': len(self.categorized_urls['known']),
                'total_hidden': len(self.categorized_urls['hidden']),
                'total_internal': len(self.categorized_urls['internal']),
                'total_external': len(self.categorized_urls['external']),
                'total_extensions': sum(len(ext) for ext in self.categorized_extensions.values())
            }
        }

        try:
            with open(self.output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Colors.GREEN}[+] Results saved to: {self.output_file}{Colors.END}")
            self.logger.info(f"Results saved to: {self.output_file}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving results: {e}{Colors.END}")
            self.logger.error(f"Error saving results: {e}")

    def print_summary(self) -> None:
        """Print extraction summary"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}" + "="*70)
        print(" "*20 + "EXTRACTION SUMMARY")
        print("="*70 + f"{Colors.END}")

        print(f"{Colors.WHITE}Target: {Colors.GREEN}{self.target_url}{Colors.END}")
        print(f"{Colors.WHITE}Domain: {Colors.GREEN}{self.domain}{Colors.END}")
        print(f"{Colors.WHITE}Total URLs: {Colors.BOLD}{Colors.GREEN}{len(self.urls)}{Colors.END}")
        print(f"{Colors.WHITE}WAF Bypass: {Colors.YELLOW}{'Enabled' if self.waf_bypass else 'Disabled'}{Colors.END}")
        print()

        print(f"{Colors.BOLD}{Colors.MAGENTA}CATEGORIZED URLs:{Colors.END}")
        for category, urls in self.categorized_urls.items():
            color = Colors.GREEN if len(urls) > 0 else Colors.RED
            print(f"  {Colors.CYAN}{category.capitalize()}: {color}{len(urls)} URLs{Colors.END}")

        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}CATEGORIZED EXTENSIONS:{Colors.END}")

        for category, extensions in self.categorized_extensions.items():
            if extensions:
                print(f"  {Colors.YELLOW}{category.upper()}:{Colors.END}")
                sorted_ext = sorted(extensions.items(), key=lambda x: x[1], reverse=True)
                for ext, count in sorted_ext[:5]:  # Top 5 per category
                    print(f"    {Colors.GREEN}.{ext}: {Colors.WHITE}{count}{Colors.END}")
                if len(sorted_ext) > 5:
                    print(f"    {Colors.CYAN}... and {len(sorted_ext) - 5} more{Colors.END}")

        print()
        print(f"{Colors.BOLD}{Colors.BLUE}TOP FILE EXTENSIONS (Overall):{Colors.END}")
        all_ext = defaultdict(int)
        for category_ext in self.categorized_extensions.values():
            for ext, count in category_ext.items():
                all_ext[ext] += count

        sorted_ext = sorted(all_ext.items(), key=lambda x: x[1], reverse=True)
        for ext, count in sorted_ext[:10]:  # Top 10 overall
            print(f"  {Colors.GREEN}.{ext}: {Colors.WHITE}{count}{Colors.END}")

        if len(sorted_ext) > 10:
            print(f"  {Colors.CYAN}... and {len(sorted_ext) - 10} more{Colors.END}")

        self.logger.info(f"Extraction completed. Total URLs: {len(self.urls)}")

def main():
    parser = argparse.ArgumentParser(
        description="Pure Python URL Extractor - Extract all URLs and extensions from target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.BOLD}Examples:{Colors.END}
  python url_extractor.py https://example.com
  python url_extractor.py https://example.com -o results.json -v -p 50 -d 2 -t 5
  python url_extractor.py https://example.com --waf-bypass --delay 2.0 --log-file custom.log

{Colors.BOLD}Author:{Colors.END} Kilo Code
        """
    )
    parser.add_argument('target_url', help='Target URL to extract URLs from')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-p', '--max-pages', type=int, default=100, help='Maximum pages to crawl (default: 100)')
    parser.add_argument('-d', '--max-depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--waf-bypass', action='store_true', help='Enable WAF bypass techniques')
    parser.add_argument('--log-file', help='Custom log file path')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    args = parser.parse_args()

    # Setup logging
    log_file = setup_logging(args.log_file)
    logger = logging.getLogger('URLExtractor')

    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')

    logger.info(f"Starting URL Extractor v5.0 by ArkhAngelLifeJiggy")
    logger.info(f"Target: {args.target_url}")

    try:
        extractor = PureURLExtractor(
            args.target_url,
            args.output,
            args.verbose,
            args.max_pages,
            args.max_depth,
            args.threads,
            getattr(args, 'delay', 1.0),
            getattr(args, 'waf_bypass', True)
        )

        start_time = time.time()
        extractor.extract()
        extractor.print_summary()

        if args.output:
            extractor.save_results()

        end_time = time.time()
        duration = end_time - start_time
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Extraction completed in {duration:.2f} seconds{Colors.END}")
        logger.info(f"Extraction completed in {duration:.2f} seconds")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Extraction interrupted by user{Colors.END}")
        logger.warning("Extraction interrupted by user")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.END}")
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()