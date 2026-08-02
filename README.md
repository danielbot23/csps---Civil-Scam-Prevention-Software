CSPS (Civil Scam Prevention Software)
=====================================

CSPS is a forensic-grade, multi-vector impersonation detection engine. This tool moves beyond generic spam filters by analyzing the specific, documented signatures of active fraud patterns and generating a probabilistic confidence score alongside how to deal with them, it’s mainly built for older people as they are more tech illiterate and are targets to scams I made it so it’s easy to understand.

Overview
--------
Government and corporate impersonation scams cost victims hundreds of millions annually. Modern attackers utilize real public data paired with urgent, non-standard payment demands. Generic spam checkers often miss these because the text appears highly localized and contextually accurate. CSPS acts as an automated digital forensics and incident response (DFIR) tool to combat these sophisticated attacks.

Core Detection Layers
---------------------
* Domain & Cryptographic Analysis: Evaluates domain typosquatting, homoglyph attacks, recent RDAP registrations, and parses raw email headers for SPF, DKIM, and DMARC alignment failures.
* Payment Vector Flagging: Identifies high-risk, non-reversible payment demands including cryptocurrency, wire transfers, peer-to-peer apps, and sudden ACH routing changes.
* NLP Pressure Scoring: Leverages sentiment analysis and pattern matching to detect extreme urgency, threats of legal action, or manipulative phrasing.
* Multi-Vector Context Routing: Dynamically identifies the attack context (e.g., Civic Permits, Tax Audit, Tech Support, M365 Security Alert) and applies specific plausibility cross-checks.
* IOC Extraction: Automatically parses out Indicators of Compromise (Bitcoin/Ethereum wallets, malicious URLs, rogue contact emails) to generate actionable threat intel.

Architecture
------------
The project is strictly decoupled into a backend forensic engine and a lightweight frontend dashboard to ensure evidence integrity.

* The Backend (Forensic Engine): A Python-based FastAPI microservice. To maintain the chain of custody, every scan generates a SHA-256 cryptographic hash of the input text and logs the event securely to a local SQLite database (csps_audit.db).
* The Frontend (Client Dashboard): A vanilla HTML/JS client interface communicating with the API via REST, providing a clean dashboard for real-time analysis without exposing the core database.

System Modules
--------------
api_server.py         - FastAPI application wrapper serving the forensic engine.
scan_notice.py        - The core scoring logic tying all detection modules together.
domain_analyzer.py    - Typosquatting, homoglyph detection, and RDAP registration checks.
header_verifier.py    - Cryptographic signature validation (SPF/DKIM/DMARC).
plausibility_check.py - Contextual routing for multi-vector scam detection.
payment_flagger.py    - Regex flagging for high-risk payment/routing demands.
pressure_scorer.py    - NLP sentiment analysis and urgency pattern matching.
ioc_extractor.py      - Threat intelligence extraction for wallets and URLs.
audit_log.py          - SQLite integration and SHA-256 hashing for immutable logging.
index.html            - The interactive dashboard connecting to the API.
requirements.txt      - Python dependencies required for the engine.

Setup and Installation
----------------------
1. Enter the directory using cd

2. Install Dependencies: 
   pip3 install -r requirements.txt

3. run the server using python3 ai_server.py

4. Start the Software by opening index.html

Project Details
---------------
Built for The RLC Hacks 2026.
