import sys
import os
import traceback

# Ensure project root is on path
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from DD_FEATURE_EXTRACTOR_09_21_2025 import PhishingFeatureExtractor

FEATURES = [
    "ip_in_url", "url_length", "url_shortening", "presence_at", "redirection_symbol",
    "hyphen_in_domain", "too_many_subdomains", "https_in_string", "ssl_tls_validity",
    "domain_registration_length", "non_standard_ports", "external_favicon", "count_dots",
    "suspicious_chars", "known_logo", "use_script", "count_third_party_domains", "use_meta",
    "script_external_ratio", "use_form", "mailto", "website_forwarding", "status_bar",
    "right_click_disabled", "popups", "iframes", "sensitive_forms", "domain_age", "dns_record",
    "traffic_rank", "page_ranking", "google_index", "backlinks", "blacklist", "whois_suspicious_tokens"
]

TEST_URLS = [
    # Standard URLs and SSL/TLS tests
    "https://www.google.com",  # Legitimate HTTPS site, high traffic rank, many backlinks
    "http://example.com",      # Non-HTTPS site
    
    # IP and port features
    "http://192.168.1.1",      # IP in URL
    "http://example.com:8080", # Non-standard port
    "https://example.com:443", # Standard HTTPS port
    
    # URL shorteners and redirections
    "https://bit.ly/abc123",   # URL shortening service
    "https://tinyurl.com/xyz", # Another URL shortener
    "https://goo.gl/short",    # Google URL shortener
    
    # Special characters and structure tests
    "http://user:pass@malicious.com",            # @ symbol in URL
    "http://sub1.sub2.sub3.example.com",         # Multiple subdomains
    "http://my-hyphenated-domain.com",           # Hyphen in domain
    "http://example.com/page?param1=1&param2=2", # Multiple parameters
    "http://example.com/path%20with%20spaces",   # URL encoding
    
    # Domain age and registration
    "https://microsoft.com",    # Old domain, long registration
    "https://facebook.com",     # Well-established domain
    
    # HTML and script features
    "https://login.live.com",   # Forms, scripts, security features
    "https://github.com",       # Complex web app with many features
    
    # Third-party content
    "https://wordpress.com",    # Many third-party resources
    "https://medium.com",       # External scripts and resources
    
    # Known phishing patterns
    "http://paypal-secure.evil.com",          # Suspicious domain name
    "http://banking.com-secure.info",         # Deceptive subdomain
    "http://login.microsoft.com.malicious.ru", # Lookalike domain
    
    # Search engine presence
    "https://wikipedia.org",     # High Google index, many backlinks
    "https://amazon.com",        # High traffic rank
    
    # Security features
    "https://mail.google.com",   # Strong security, SSL
    "https://online.chase.com",  # Banking site with security features
    
    # Specific feature tests
    "https://example.com/favicon-external.ico",  # External favicon
    "https://example.com/page.php?redirect=true", # Redirection
    "https://example.com/contact?mailto=true",    # Mailto link
    "https://example.com/popup.html",            # Popup windows
    "https://example.com/iframe-test.html",      # iframes
    
    # Known malicious patterns (for testing only)
    "http://suspicious-login.com/form.php",      # Sensitive forms
    "http://phishing-attempt.net/bank/login",    # Banking keywords
    "http://malware.testing.google.test/test",   # Blacklist testing
    
    # Additional edge cases
    "https://xn--80ak6aa92e.com",              # Punycode domain
    "https://site.with.multiple.dots.com",      # Multiple dots
    "http://example.com//.info//redirect",      # Multiple slashes
]

def test_url(url):
    print(f"\nTesting features for URL: {url}")
    print("-" * 80)

    ext = PhishingFeatureExtractor(url=url)
    results = {}
    errors = {}

    for feat in FEATURES:
        try:
            fn = getattr(ext, feat)
            val = fn()
            results[feat] = val
            print(f"{feat:30} : {val}")
        except Exception as e:
            errors[feat] = str(e)
            print(f"{feat:30} : ERROR -> {e}")
            traceback.print_exc()

    print("\nTesting extract_all()...")
    print("-" * 80)
    try:
        all_res = ext.extract_all()
        for k, v in all_res.items():
            print(f"{k:30} : {v}")
            if k in results and results[k] != v:
                print(f"WARNING: Mismatch between individual call ({results[k]}) and extract_all ({v})")
    except Exception as e:
        print("extract_all ERROR:", e)
        traceback.print_exc()

    return results, errors

def main():
    url = os.environ.get('TEST_URL')
    if url:
        test_url(url)
    else:
        total_success = 0
        total_errors = 0
        
        for url in TEST_URLS:
            print(f"\n{'='*100}")
            print(f"Testing URL: {url}")
            print(f"{'='*100}")
            results, errors = test_url(url)
            total_success += len(results)
            total_errors += len(errors)
        
        print(f"\n{'='*100}")
        print(f"Final Summary:")
        print(f"Total features tested: {len(FEATURES)}")
        print(f"Total successes: {total_success}")
        print(f"Total errors: {total_errors}")
        print(f"Success rate: {(total_success/(total_success+total_errors))*100:.1f}%")

if __name__ == "__main__":
    main()
