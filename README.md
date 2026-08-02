# CSPS (Civil Scam Prevention Software)

Checks a suspicious government/permit notice against the specific fraud
pattern using methods stated by the FBI

## The problem

Government impersonation scams basically doubled between 2024 and 2025,
with about $800 million lost. The FBI issued a specific alert this year
about scammers impersonating city and county planning and zoning
officials, sending fake permit fee invoices. What makes these convincing
is that they use real details, actual property addresses, real case
numbers, and the true names of real officials, pulled from public permit
portals. The emails come from domains that look real and legit at a glance
but aren’t official government domains, and they push for payment
through wire transfer, crypto, or peer to peer apps and gift cards none of which real
government offices accept.

Generic scam checker tools already exist, but they’re built for
all-purpose message scanning. To my knowledge Nothing is built specifically around this
exact, currently active pattern.

## The solution

This project checks a notice against four layers, based directly on
what the FBI’s alert actually described, not generic scam heuristics.

**Domain analysis** checks the sender’s domain against known scam
domains and looks for typosquatting tricks, like a digit swapped in for
a letter to fake a legitimate-looking domain.

**Payment method flagging** looks for wire transfer, crypto, gift card,
or P2P app requests. Real permit offices don’t accept these, so this
flag alone is a strong signal.

**Pressure language scoring** looks for the urgency and threat phrasing
scammers use to stop someone from pausing to verify first, things like
“immediately,” “avoid penalties,” or “failure to pay will result in.”

**Plausibility cross-check** is the layer built directly from the FBI’s
actual description of this scam. Real-looking case numbers or addresses
alone aren’t suspicious. Urgency alone isn’t either. But all three,
specific details plus urgency plus an unusual payment method, together
is the documented signature of this exact fraud pattern.

All four layers feed into a weighted score, Low, Medium, or High risk,
along with a plain-language breakdown of exactly which signals fired
and why, instead of a black box yes or no.

## What’s in this repo

|File                   |What it does                                                        |
|-----------------------|--------------------------------------------------------------------|
|`domain_analyzer.py`   |Checks sender domain for known scam patterns and typosquat tricks.  |
|`payment_flagger.py`   |Flags requests for wire transfer, crypto, gift cards, or P2P apps.  |
|`pressure_scorer.py`   |Flags urgency and threat language.                                  |
|`plausibility_check.py`|Checks for the specific FBI-documented combo pattern.               |
|`scan_notice.py`       |Runs all four layers and produces the final scored report.          |
|`index.html`           |Web version of the same detection logic, for a live demo in browser.|
|`requirements.txt`     |Dependencies (none needed, standard library only).                  |

`index.html` is a direct port of the Python detection logic to
JavaScript, not a separate or simplified tool. Same four layers, same
weights, same patterns, verified to produce identical results to the
Python version. The Python files are the original engine; the web
version is a presentation layer built on top of it for a live,
click-through demo.

## Running it

```bash
python3 scan_notice.py
```

Runs a clean baseline notice and a notice built from the real
FBI-documented pattern side by side, so you can see both a clean result
and a flagged one in the same run. No internet connection or API key
needed, everything runs locally on plain text pattern matching.

To see the web version instead, open `index.html` directly in a
browser, or visit the hosted version if this repo has GitHub Pages
enabled.

## Future plans

The domain and phrase lists here are a small, hand-built starting set,
not a comprehensive database. A real version would pull from an actual
municipal domain registry and expand the pattern lists as new scam
variations get documented, since scammers adjust their wording once a
pattern becomes well known.

The bigger point is the approach itself. Instead of trying to catch
scams with a single generic rule, this checks for the specific,
documented signature of an active fraud pattern, and shows the reasoning
behind the flag instead of just a risk label. That same approach, tuned
to the specifics of a real, currently active scam, could extend to other
impersonation patterns the FBI or FTC document as they show up, not just
this one.

## Built for The RLC Hacks 2026