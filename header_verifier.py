import re

def analyze_headers(raw_headers):
    flags = []
    if not raw_headers or raw_headers.strip() == "":
        return flags

    auth_results_match = re.search(r"Authentication-Results:(.*?)(?:\n\S|\Z)", raw_headers, re.IGNORECASE | re.DOTALL)
    
    if auth_results_match:
        auth_text = auth_results_match.group(1).lower()
        if "spf=fail" in auth_text or "spf=softfail" in auth_text:
            flags.append("SPF alignment failed (Sender IP not authorized by domain)")
        if "dkim=fail" in auth_text:
            flags.append("DKIM cryptographic signature failed (Message may be tampered/spoofed)")
        if "dmarc=fail" in auth_text:
            flags.append("DMARC policy failed (Domain impersonation detected)")
    else:
        flags.append("Missing Authentication-Results header (Cannot verify cryptographic sender identity)")

    return flags
