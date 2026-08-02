import re
import urllib.request
import json
import datetime
from urllib.error import URLError

KNOWN_GOV_PATTERNS = [ r"\.gov$", r"\.state\.[a-z]{2}\.us$", r"\.us$" ]
SUSPICIOUS_DOMAINS = [ "usa.com", "gov-portal.com", "govservices.net", "cityhall-services.com" ]
DIGIT_LOOKALIKES = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}

def extract_domain(sender_email):
    match = re.search(r"@([\w\.-]+)", sender_email)
    return match.group(1).lower() if match else sender_email.lower()

def levenshtein(a, b):
    if len(a) < len(b): return levenshtein(b, a)
    if len(b) == 0: return len(a)
    prev_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        curr_row = [i + 1]
        for j, cb in enumerate(b):
            insert, delete, sub = prev_row[j + 1] + 1, curr_row[j] + 1, prev_row[j] + (ca != cb)
            curr_row.append(min(insert, delete, sub))
        prev_row = curr_row
    return prev_row[-1]

def looks_like_gov(domain):
    return any(re.search(p, domain) for p in KNOWN_GOV_PATTERNS)

def check_typosquat(domain, reference_domains, max_distance=2):
    hits = []
    for ref in reference_domains:
        dist = levenshtein(domain, ref)
        if 0 < dist <= max_distance: hits.append((ref, dist))
    return hits

def check_brand_impersonation(domain, reference_domains, min_brand_len=4):
    """Catches 'brand + extra words' domains like 'microsoft-support.com',
    which aren't close enough in edit-distance to be caught as a typo,
    but do contain a real, known brand name they have no right to use."""
    hits = []
    for ref in reference_domains:
        brand = ref.split(".")[0]
        if len(brand) < min_brand_len:
            continue
        if brand in domain and domain != ref and not domain.endswith("." + ref):
            hits.append((ref, brand))
    return hits

def check_homoglyphs(domain):
    sandwiched = re.findall(r"[a-z]\d[a-z]", domain)
    if not sandwiched: return False, domain
    swapped = domain
    for fake, real in DIGIT_LOOKALIKES.items(): swapped = swapped.replace(fake, real)
    return True, swapped

def check_rdap_registration(domain):
    if looks_like_gov(domain): return False, None
    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(url, headers={'User-Agent': 'CSPS-Analyzer/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            for event in data.get('events', []):
                if event.get('eventAction') == 'registration':
                    reg_date_str = event.get('eventDate')
                    if reg_date_str:
                        reg_date = datetime.datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
                        age_days = (datetime.datetime.now() - reg_date).days
                        if age_days < 90:
                            return True, f"domain is newly registered ({age_days} days old, high risk)"
    except (URLError, json.JSONDecodeError, KeyError):
        pass
    return False, None

def analyze_domain(sender_email, reference_domains=None):
    """Returns (risk_flags, info_notes). risk_flags are scored/counted toward
    the risk %. info_notes are neutral context shown to the user but never
    inflate the score on their own — being non-.gov isn't, by itself, suspicious."""
    domain = extract_domain(sender_email)
    reference_domains = reference_domains or []
    risk_flags = []
    info_notes = []

    if domain in SUSPICIOUS_DOMAINS:
        risk_flags.append(f"domain '{domain}' matches a known scam sender pattern")

    if not looks_like_gov(domain) and reference_domains:
        typosquat_hits = check_typosquat(domain, reference_domains)
        if typosquat_hits:
            closest, dist = min(typosquat_hits, key=lambda x: x[1])
            risk_flags.append(f"domain '{domain}' is suspiciously close to real domain '{closest}' (edit distance {dist})")

        brand_hits = check_brand_impersonation(domain, reference_domains)
        if brand_hits:
            ref, brand = brand_hits[0]
            risk_flags.append(f"domain '{domain}' uses the brand name '{brand}' but isn't {ref} — a common impersonation trick")

    has_homoglyph, swapped = check_homoglyphs(domain)
    if has_homoglyph: risk_flags.append(f"domain '{domain}' contains lookalike characters (reads as '{swapped}')")

    is_new, rdap_flag = check_rdap_registration(domain)
    if is_new: risk_flags.append(rdap_flag)

    if not looks_like_gov(domain) and not risk_flags:
        info_notes.append(f"'{domain}' isn't a .gov address — that's normal for most senders, but worth confirming if this claims to be from a government office.")

    return risk_flags, info_notes
