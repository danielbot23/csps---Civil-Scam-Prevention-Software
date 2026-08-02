from domain_analyzer import analyze_domain
from payment_flagger import flag_payment_method
from pressure_scorer import score_pressure
from plausibility_check import check_combo
from ioc_extractor import extract_iocs
from header_verifier import analyze_headers
import audit_log 

REFERENCE_GOV_DOMAINS = ["city.gov", "county.gov", "sonomacounty.gov", "usa.gov", "microsoft.com"]

CONFIDENCE_WEIGHTS = {
    "domain": 0.35, "header": 0.15, "payment": 0.30, "pressure": 0.05, "combo": 0.15,
}

GUIDANCE = {
    "HIGH": "This has strong warning signs of a scam. Please don't click links, send payment, or share personal info. Verify independently through an official number or website you already trust.",
    "MEDIUM": "A few things here are worth double-checking before you act. Nothing confirmed yet — just verify through an official source first.",
    "LOW": "One small thing stood out, but nothing alarming. Trust your instincts, and verify independently if anything feels off.",
    "CLEAN": "Nothing suspicious found. This looks safe to proceed with as normal.",
}

def score_notice(sender_email, body_text, raw_headers=""):
    domain_flags, domain_context = analyze_domain(sender_email, REFERENCE_GOV_DOMAINS)
    payment_flags = flag_payment_method(body_text)
    pressure_flags = score_pressure(body_text)
    combo_hit, combo_reason = check_combo(body_text, payment_flags, pressure_flags)
    header_flags = analyze_headers(raw_headers)
    extracted_iocs = extract_iocs(body_text)

    confidence = 0.0
    breakdown = []

    if header_flags:
        confidence += CONFIDENCE_WEIGHTS["header"]
        breakdown.append(("Email authenticity", header_flags))
    if domain_flags:
        confidence += CONFIDENCE_WEIGHTS["domain"]
        breakdown.append(("Sender check", domain_flags))
    if payment_flags:
        confidence += CONFIDENCE_WEIGHTS["payment"]
        breakdown.append(("Payment request", [f"asks for payment via: {h}" for h in payment_flags]))
    if pressure_flags:
        confidence += CONFIDENCE_WEIGHTS["pressure"]
        breakdown.append(("Urgency & tone", [f"pressure tactic noticed: {h}" for h in pressure_flags]))
    if combo_hit:
        confidence += CONFIDENCE_WEIGHTS["combo"]
        breakdown.append(("Known scam pattern", [combo_reason]))

    confidence = min(confidence, 0.999)

    if confidence >= 0.75: risk = "HIGH"
    elif confidence >= 0.40: risk = "MEDIUM"
    elif confidence > 0.0: risk = "LOW"
    else: risk = "CLEAN"

    confidence_pct = round(confidence * 100, 1)
    audit_log.log_scan(sender_email, body_text, risk, confidence_pct, breakdown)

    return { 
        "risk": risk, 
        "score": f"{confidence_pct}%", 
        "breakdown": breakdown, 
        "context": domain_context,
        "guidance": GUIDANCE[risk],
        "iocs": extracted_iocs
    }
