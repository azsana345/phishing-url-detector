import re
import tldextract

def has_ip_address(url):
    ip_pattern = r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}'
    return re.search(ip_pattern, url) is not None

def has_suspicious_words(url):
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'banking', 'confirm']
    return any(word in url.lower() for word in suspicious_keywords)

def is_long_url(url):
    return len(url) > 75

def has_at_symbol(url):
    return '@' in url

def extract_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

def check_phishing(url):
    results = {
        'has_ip_address': has_ip_address(url),
        'has_suspicious_words': has_suspicious_words(url),
        'is_long_url': is_long_url(url),
        'has_at_symbol': has_at_symbol(url),
        'domain': extract_domain(url)
    }

    # Explanation reasons
    reasons = []

    if results['has_ip_address']:
        reasons.append("Uses an IP address instead of a domain.")
    if results['has_suspicious_words']:
        reasons.append("Contains suspicious keywords like 'login', 'verify', or 'update'.")
    if results['is_long_url']:
        reasons.append("The URL is unusually long.")
    if results['has_at_symbol']:
        reasons.append("Uses '@' symbol which can be used for redirection.")

    true_count = sum([
        results['has_ip_address'],
        results['has_suspicious_words'],
        results['is_long_url'],
        results['has_at_symbol']
    ])

    score = (true_count / 4) * 100
    results['phishing_score'] = round(score, 2)
    results['is_phishing'] = score >= 50
    results['reasons'] = reasons if reasons else ["No suspicious patterns detected."]

    return results
