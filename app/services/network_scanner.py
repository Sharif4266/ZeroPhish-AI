import socket
import ssl
import whois
import requests
import datetime
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

def get_network_intelligence(url: str) -> dict:
    """
    Perform deep network scanning on a URL to get:
    - IP Address
    - Redirect Chain
    - SSL Certificate Status
    - Domain Age
    """
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]  # remove port if present

    result = {
        "url": url,
        "domain": domain,
        "ip_address": None,
        "redirect_chain": [],
        "ssl_status": "Not Checked",
        "domain_age_days": None,
        "creation_date": None,
        "error": None
    }

    if not domain:
        result["error"] = "Invalid URL domain"
        return result

    # 1. IP Address Resolution
    try:
        ip = socket.gethostbyname(domain)
        result["ip_address"] = ip
    except Exception as e:
        logger.warning(f"Failed to resolve IP for {domain}: {e}")

    # 2. Redirect Chain tracking
    try:
        # User-Agent to avoid immediate blocks from simple anti-bot protections
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
        
        # Build chain
        chain = []
        if response.history:
            for i, r in enumerate(response.history):
                chain.append({
                    "step": i + 1,
                    "url": r.url,
                    "status_code": r.status_code
                })
        
        # Add final destination
        chain.append({
            "step": len(chain) + 1,
            "url": response.url,
            "status_code": response.status_code,
            "is_final": True
        })
        result["redirect_chain"] = chain

    except requests.exceptions.RequestException as e:
        logger.warning(f"Request failed for {url}: {e}")
        # If request fails, at least register the initial hop
        result["redirect_chain"] = [{
            "step": 1,
            "url": url,
            "status_code": "Failed",
            "is_final": True
        }]

    # 3. SSL Certificate check
    if parsed.scheme == 'https' or len(result["redirect_chain"]) > 0 and result["redirect_chain"][-1]["url"].startswith('https'):
        # Check SSL for the final domain
        final_domain = urlparse(result["redirect_chain"][-1]["url"]).netloc.split(':')[0]
        try:
            context = ssl.create_default_context()
            with socket.create_connection((final_domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=final_domain) as ssock:
                    cert = ssock.getpeercert()
                    # If we got here, the cert is valid and trusted by the system
                    result["ssl_status"] = "Valid / Trusted"
        except ssl.SSLCertVerificationError:
            result["ssl_status"] = "Invalid / Self-Signed"
        except Exception as e:
            result["ssl_status"] = f"Error or No SSL"
            logger.warning(f"SSL check failed for {final_domain}: {e}")
    else:
        result["ssl_status"] = "No SSL (HTTP)"

    # 4. WHOIS Domain Age
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if type(creation_date) == list:
            creation_date = creation_date[0]
            
        if creation_date:
            age = (datetime.datetime.now() - creation_date).days
            result["domain_age_days"] = age
            result["creation_date"] = creation_date.isoformat()
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")

    return result
