import re

CONTEXT_PATTERNS = {
    "PERMIT_OR_ZONING": [
        r"case (number|#|no\.?)\s*[:\-]?\s*\w+",
        r"permit (number|#|no\.?)\s*[:\-]?\s*\w+",
        r"\d{1,5}\s+\w+\s+(street|st|avenue|ave|road|rd|drive|dr)",
        r"parcel (number|#|id)",
    ],
    "TAX_FRAUD": [
        r"tax (return|refund|audit)",
        r"w-2|1099",
        r"irs|internal revenue",
    ],
    "TECH_SUPPORT": [
        r"(antivirus|mcafee|norton|geek squad)",
        r"subscription (renewed|auto-renew)",
        r"invoice (number|#|no\.?)\s*[:\-]?\s*\w+",
    ],
    "MICROSOFT_365_BEC": [
        r"microsoft 365|office 365|m365",
        r"shared (a file|a document|a folder|sharepoint|onedrive)",
        r"security alert|unusual sign-in|password (expiry|expiration|reset)",
        r"tenant update|compliance policy",
    ]
}

def detect_context(text):
    identified_contexts = []
    for context, patterns in CONTEXT_PATTERNS.items():
        if any(re.search(p, text, re.IGNORECASE) for p in patterns):
            identified_contexts.append(context)
    return identified_contexts

def check_combo(text, payment_hits, pressure_hits):
    contexts = detect_context(text)
    
    if contexts and payment_hits and pressure_hits:
        context_str = ", ".join(contexts).replace("_", " ").lower()
        return True, f"matches documented multi-vector pattern ({context_str} context + urgency + non-standard payment)"

    return False, None
