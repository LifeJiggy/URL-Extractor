"""
# Basic usage with all fixes
python url_extractor.py https://example.com

# Advanced with WAF bypass (no more hanging!)
python url_extractor.py https://bugcrowd.com --waf-bypass --delay 1.5 -v

# Full security scan with complete JSON output
python url_extractor.py https://target.com \
  --waf-bypass \
  --delay 2.0 \
  --max-pages 500 \
  --verbose \
  --output complete_scan.json \
  --log-file security_scan.log

"""