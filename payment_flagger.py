import re

RISKY_PAYMENT_PATTERNS = [
    r"wire transfer",
    r"wire (the )?(funds|payment|money)",
    r"crypto(currency)?",
    r"bitcoin|btc|ethereum",
    r"gift card",
    r"(zelle|venmo|cashapp|cash app)",
    r"prepaid (card|debit)",
    r"updated ach (details|instructions)",
    r"new routing number",
]

def flag_payment_method(text):
    hits = []
    for pattern in RISKY_PAYMENT_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            hits.append(match.group(0))
    return hits
