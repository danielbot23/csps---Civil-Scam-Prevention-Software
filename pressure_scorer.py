import re

try:
    from textblob import TextBlob
    HAS_NLP = True
except ImportError:
    HAS_NLP = False

PRESSURE_PATTERNS = [
    r"immediately",
    r"avoid (delays|penalties|fines|suspension)",
    r"failure to (pay|respond|comply).{0,30}(result|lead)",
    r"within 24 hours",
    r"final notice",
    r"account (will be|has been) (suspended|frozen|closed)",
    r"legal action",
    r"do not (ignore|delay)",
]

def score_pressure(text):
    hits = []
    
    for pattern in PRESSURE_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            hits.append(match.group(0))
            
    if HAS_NLP:
        blob = TextBlob(text)
        if blob.sentiment.polarity <= -0.3:
            hits.append("NLP detected highly negative/threatening sentiment anomaly")
            
    return hits
