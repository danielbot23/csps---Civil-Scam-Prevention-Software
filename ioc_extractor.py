import re

def extract_iocs(text):
    iocs = {
        "crypto_wallets": [],
        "urls": [],
        "emails": []
    }
    
    btc_pattern = r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b"
    eth_pattern = r"\b(0x[a-fA-F0-9]{40})\b"
    url_pattern = r"(https?://[^\s]+)"
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

    for match in re.finditer(btc_pattern, text):
        iocs["crypto_wallets"].append({"type": "Bitcoin", "address": match.group(0)})
        
    for match in re.finditer(eth_pattern, text):
        iocs["crypto_wallets"].append({"type": "Ethereum", "address": match.group(0)})

    for match in re.finditer(url_pattern, text):
        iocs["urls"].append(match.group(0))
        
    for match in re.finditer(email_pattern, text):
        iocs["emails"].append(match.group(0))

    return iocs
