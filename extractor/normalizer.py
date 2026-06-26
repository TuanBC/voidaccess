"""
extractor/normalizer.py — Entity deduplication and canonical record merging.

The same wallet address may appear in 50 pages; it gets one NormalizedEntity
per call to normalize_entities() (deduped by canonical value within that call).
merge_with_db() upserts records to the DB and returns the assigned IDs.

Public interface
----------------
normalize_entities(raw_entities, page_url, page_id) → list[NormalizedEntity]
merge_with_db(entities, investigation_id)            → list  (DB IDs / empty)
resolve_entity_type_conflicts(entities)             → list  (deduped by canonical value)
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List
import uuid

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical type priority for conflict resolution
# Lower number = higher specificity, wins in conflicts
# ---------------------------------------------------------------------------

TYPE_PRIORITY = {
    "CVE": 1,
    "MITRE_TECHNIQUE": 1,
    "MITRE_TACTIC": 1,
    "FILE_HASH_SHA256": 1,
    "FILE_HASH_SHA1": 1,
    "FILE_HASH_MD5": 1,
    "IP_ADDRESS": 1,
    "IPV6_ADDRESS": 1,
    "MAC_ADDRESS": 1,
    "IPFS_CID": 1,
    "EXPLOIT_DB_ID": 1,
    "YARA_RULE": 2,
    "NUCLEI_TEMPLATE": 2,
    "ONION_URL": 1,
    # Credential / token IOCs — high specificity, high value, priority 1.
    "AWS_ACCESS_KEY": 1,
    "AWS_SECRET_KEY": 1,
    "GITHUB_TOKEN": 1,
    "SLACK_TOKEN": 1,
    "DISCORD_TOKEN": 1,
    "JWT_TOKEN": 1,
    "GOOGLE_API_KEY": 1,
    "STRIPE_KEY": 1,
    "STEALER_LOG_ENTRY": 1,
    # Messaging / identity handle IOCs — high specificity shapes.  XMPP_JID
    # at priority 1 means an "xmpp: user@host" address wins over a plain
    # EMAIL_ADDRESS (priority 4) when the same value would qualify as both.
    "TELEGRAM_HANDLE": 1,
    "DISCORD_HANDLE": 1,
    "XMPP_JID": 1,
    "TOX_ID": 1,
    "SESSION_ID": 1,
    "MATRIX_HANDLE": 1,
    "BITCOIN_ADDRESS": 2,
    "MONERO_ADDRESS": 2,
    "ETH_ADDRESS": 2,
    "ETHEREUM_ADDRESS": 2,
    "LITECOIN_ADDRESS": 2,
    "ZCASH_ADDRESS": 2,
    "DOGECOIN_ADDRESS": 2,
    "XRP_ADDRESS": 2,
    "SOLANA_ADDRESS": 2,
    "TRON_ADDRESS": 2,
    "BITCOIN_CASH_ADDRESS": 2,
    "DASH_ADDRESS": 2,
    "ENS_DOMAIN": 2,
    "API_KEY": 2,  # generic — slightly broader pattern, lower priority than vendor-specific
    # Context-dependent messaging handles — slightly lower priority than the
    # shape-specific ones above because they require a context keyword.
    "WIRE_HANDLE": 2,
    "ICQ_NUMBER": 2,
    "WICKR_ID": 2,
    "COMBO_LIST_ENTRY": 1,
    "CRYPTO_SEED_PHRASE": 1,
    "RANSOMWARE_GROUP": 3,
    "THREAT_ACTOR": 3,
    "MALWARE_FAMILY": 3,
    "EMAIL_ADDRESS": 4,
    "PGP_KEY_BLOCK": 4,
    "DOMAIN": 5,
    "ORGANIZATION_NAME": 6,
    "PERSON_NAME": 6,
    "LOCATION": 7,
}
DEFAULT_PRIORITY = 99

# Tiebreak order when types have equal priority
TIEBREAK_ORDER = [
    "RANSOMWARE_GROUP",
    "THREAT_ACTOR",
    "MALWARE_FAMILY",
    "FILE_HASH_SHA256",
    "FILE_HASH_SHA1",
    "FILE_HASH_MD5",
    "CVE",
    "MITRE_TECHNIQUE",
    "IP_ADDRESS",
    "ONION_URL",
    # Credentials — vendor-specific wins over generic in a tie.
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "SLACK_TOKEN",
    "DISCORD_TOKEN",
    "JWT_TOKEN",
    "GOOGLE_API_KEY",
    "STRIPE_KEY",
    "STEALER_LOG_ENTRY",
    "API_KEY",
    # Messaging / identity handles — placed next to credentials in the
    # tiebreak ladder so shape-specific messaging IOCs outrank EMAIL.
    "TELEGRAM_HANDLE",
    "DISCORD_HANDLE",
    "XMPP_JID",
    "TOX_ID",
    "SESSION_ID",
    "MATRIX_HANDLE",
    "WIRE_HANDLE",
    "ICQ_NUMBER",
    "WICKR_ID",
    # Network / forensic identifiers (Phase 2 — final subphase).  All
    # placed near the high-specificity IOCs at the top of the tiebreak
    # ladder so they win against generic types when the same value
    # would qualify as more than one entity.
    "IPV6_ADDRESS",
    "MAC_ADDRESS",
    "IPFS_CID",
    "EXPLOIT_DB_ID",
    "YARA_RULE",
    "NUCLEI_TEMPLATE",
    "MITRE_TACTIC",
    "COMBO_LIST_ENTRY",
    "CRYPTO_SEED_PHRASE",
    "EMAIL_ADDRESS",
    "PGP_KEY_BLOCK",
    "BITCOIN_ADDRESS",
    "ETHEREUM_ADDRESS",
    "MONERO_ADDRESS",
    "LITECOIN_ADDRESS",
    "ZCASH_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",
    "SOLANA_ADDRESS",
    "TRON_ADDRESS",
    "BITCOIN_CASH_ADDRESS",
    "DASH_ADDRESS",
    "ENS_DOMAIN",
    "DOMAIN",
    "ORGANIZATION_NAME",
    "PERSON_NAME",
    "LOCATION",
]


def _get_priority(entity_type: str) -> int:
    return TYPE_PRIORITY.get(entity_type, DEFAULT_PRIORITY)


def _get_tiebreak_rank(entity_type: str) -> int:
    try:
        return TIEBREAK_ORDER.index(entity_type)
    except ValueError:
        return len(TIEBREAK_ORDER)


def resolve_entity_type_conflicts(entities: list) -> list:
    """
    Resolve entity type conflicts by keeping only the most specific type
    for each unique canonical value.

    When the same value appears with multiple types:
    - Lower TYPE_PRIORITY wins (higher specificity)
    - Equal priority resolved by TIEBREAK_ORDER
    """
    value_to_entities: dict[str, list] = {}
    for entity in entities:
        key = entity.value.lower()
        if key not in value_to_entities:
            value_to_entities[key] = []
        value_to_entities[key].append(entity)

    resolved = []
    for value_lower, group in value_to_entities.items():
        if len(group) == 1:
            resolved.append(group[0])
            continue

        type_to_entity = {}
        for entity in group:
            et = entity.entity_type
            if et not in type_to_entity:
                type_to_entity[et] = entity
            else:
                existing = type_to_entity[et]
                if entity.confidence > existing.confidence:
                    type_to_entity[et] = entity

        conflicting_types = list(type_to_entity.keys())
        if len(conflicting_types) == 1:
            resolved.append(type_to_entity[conflicting_types[0]])
            continue

        def _sort_key(t):
            return (_get_priority(t), _get_tiebreak_rank(t))

        conflicting_types.sort(key=_sort_key)
        winner_type = conflicting_types[0]
        winner = type_to_entity[winner_type]

        logger.debug(
            f"Type conflict: '{winner.value}' resolved from {conflicting_types} to {winner_type}"
        )
        resolved.append(winner)

    return resolved


def _validate_hash_length(entity_type: str, value: str) -> bool:
    """Validate that a hash entity has the correct length for its type."""
    if entity_type == "FILE_HASH_MD5":
        return len(value) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", value) is not None
    elif entity_type == "FILE_HASH_SHA1":
        return len(value) == 40 and re.fullmatch(r"[0-9a-fA-F]{40}", value) is not None
    elif entity_type == "FILE_HASH_SHA256":
        return len(value) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None
    return True


def _validate_onion_url(value: str) -> bool:
    """Return True only if value is a valid .onion address."""
    value = value.lower().strip()
    if not value.endswith(".onion") and ".onion/" not in value:
        return False
    _ONION_PATTERN = re.compile(r'^(https?://)?[a-z2-7]{16,56}\.onion(/.*)?$')
    return bool(_ONION_PATTERN.match(value))


def _validate_crypto_wallet(entity_type: str, value: str) -> bool:
    """
    Defensive shape check for the new cryptocurrency wallet types.

    The regex extractors already enforce these shapes, but this is a
    second-line check in the normalizer so a malformed value can never
    slip into the DB even if a future refactor weakens the regex.
    """
    if not value:
        return False

    if entity_type == "LITECOIN_ADDRESS":
        # L or M prefix, base58, 27-34 chars total
        return bool(re.fullmatch(r"[LM][a-km-zA-HJ-NP-Z1-9]{26,33}", value))

    if entity_type == "ZCASH_ADDRESS":
        # Transparent (t1/t3 + 33 base58) or shielded (zs1 + 74-78 [a-z0-9])
        return bool(
            re.fullmatch(r"t[13][a-km-zA-HJ-NP-Z1-9]{33}", value)
            or re.fullmatch(r"zs1[a-z0-9]{74,78}", value)
        )

    if entity_type == "DOGECOIN_ADDRESS":
        # D prefix, standard base58 (1-9 + A-Z excl I/O + a-z excl l), 26-34 chars total
        return bool(re.fullmatch(r"D[1-9A-HJ-NP-Za-km-z]{24,33}", value))

    if entity_type == "XRP_ADDRESS":
        # r prefix, 25-35 alphanumeric
        return bool(re.fullmatch(r"r[0-9a-zA-Z]{24,34}", value))

    if entity_type == "SOLANA_ADDRESS":
        # base58, 32-44 chars, no prefix
        return bool(re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", value))

    if entity_type == "TRON_ADDRESS":
        # T prefix, base58 (no 0/O/I/l), 34 chars total
        return bool(re.fullmatch(r"T[A-HJ-NP-Za-km-z1-9]{33}", value))

    if entity_type == "BITCOIN_CASH_ADDRESS":
        # cashaddr: bitcoincash:q... or bitcoincash:p... with 41-111 chars payload
        if not value.startswith("bitcoincash:"):
            return False
        payload = value[len("bitcoincash:"):]
        if len(payload) < 42 or len(payload) > 112:
            return False
        if payload[0] not in ("q", "p"):
            return False
        return bool(re.fullmatch(r"[a-z0-9]+", payload))

    if entity_type == "DASH_ADDRESS":
        # X prefix, base58 (excludes 0/O), 34 chars total
        return bool(re.fullmatch(r"X[1-9A-HJ-NP-Za-km-z]{33}", value))

    if entity_type == "ENS_DOMAIN":
        # <label>.eth, label 3-63 chars, alphanumeric + hyphen (no edge hyphens)
        if not value.lower().endswith(".eth"):
            return False
        label = value[:-4]
        if len(label) < 3 or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        return bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]", label))

    # Unknown crypto entity type — let it through (validator should be added).
    return True


def _validate_network_forensic(entity_type: str, value: str) -> bool:
    """
    Defensive shape check for the network / forensic identifier types
    added per Phase 2 (final subphase).

    The regex extractors already enforce these shapes via regex +
    validators, but this is a second line of defence so a malformed
    value can never reach the DB even if a future refactor weakens the
    regex.

    Returns True if the value passes the shape check, False otherwise.
    """
    if not value:
        return False

    if entity_type == "IPV6_ADDRESS":
        # Defer to the regex_patterns helper (handles all standard
        # forms plus the private/loopback filter).
        try:
            from extractor.regex_patterns import _is_valid_ipv6
            return _is_valid_ipv6(value)
        except Exception:
            return False

    if entity_type == "MAC_ADDRESS":
        # Canonical form is AA:BB:CC:DD:EE:FF (17 chars, 5 colons).
        return bool(re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", value))

    if entity_type == "IPFS_CID":
        # CIDv0 (Qm + 44 base58) or CIDv1 (bafy + 55-60 base32)
        return bool(
            re.fullmatch(r"Qm[1-9A-HJ-NP-Za-km-z]{44}", value)
            or re.fullmatch(r"bafy[a-z2-7]{55,60}", value)
        )

    if entity_type == "YARA_RULE":
        return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{2,127}", value))

    if entity_type == "MITRE_TACTIC":
        if not re.fullmatch(r"TA\d{4}", value):
            return False
        n = int(value[2:])
        return 1 <= n <= 43

    if entity_type == "EXPLOIT_DB_ID":
        return bool(re.fullmatch(r"[0-9]{4,6}", value))

    if entity_type == "NUCLEI_TEMPLATE":
        return bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+){2,6}", value))

    if entity_type == "COMBO_LIST_ENTRY":
        # The canonical value is the email side of an email:password
        # line.  It must look like an email and must NOT contain the
        # password-substring indicators (a downstream blocklist check
        # catches that — this is the shape check).
        return "@" in value and "." in value

    if entity_type == "CRYPTO_SEED_PHRASE":
        # The canonical value is one of two fixed marker strings.  If
        # a future refactor accidentally leaks an actual seed phrase
        # through the normalizer, we reject anything that is not one
        # of the two known marker strings.
        return value in (
            "SEED_PHRASE_DETECTED_12_WORDS",
            "SEED_PHRASE_DETECTED_24_WORDS",
        )

    return True


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Confidence scores by extraction source (inferred from entity_type)
# ---------------------------------------------------------------------------

_REGEX_TYPES: frozenset[str] = frozenset({
    "BITCOIN_ADDRESS",
    "ETHEREUM_ADDRESS",
    "MONERO_ADDRESS",
    "LITECOIN_ADDRESS",
    "ZCASH_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",
    "SOLANA_ADDRESS",
    "TRON_ADDRESS",
    "BITCOIN_CASH_ADDRESS",
    "DASH_ADDRESS",
    "ENS_DOMAIN",
    "ONION_URL",
    "EMAIL_ADDRESS",
    "PGP_KEY_BLOCK",
    "CVE_NUMBER",
    "FILE_HASH_MD5",
    "FILE_HASH_SHA1",
    "FILE_HASH_SHA256",
    "IP_ADDRESS",
    "PHONE_NUMBER",
    "PASTE_URL",
    "MITRE_TECHNIQUE",
    # Credential / token types — all bypass blocklist and use regex confidence.
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "SLACK_TOKEN",
    "DISCORD_TOKEN",
    "JWT_TOKEN",
    "GOOGLE_API_KEY",
    "STRIPE_KEY",
    "STEALER_LOG_ENTRY",
    "API_KEY",
    # Messaging / identity handle types — also bypass blocklist (their
    # shapes are precise enough to require a context-keyword check in the
    # regex extractor; the blocklist would otherwise false-positive on
    # common messaging usernames).
    "TELEGRAM_HANDLE",
    "DISCORD_HANDLE",
    "XMPP_JID",
    "TOX_ID",
    "SESSION_ID",
    "MATRIX_HANDLE",
    "WIRE_HANDLE",
    "ICQ_NUMBER",
    "WICKR_ID",
    # Network / forensic identifier types (Phase 2 — final subphase).
    # Bypass the blocklist (their shapes are precise / context-checked)
    # and use the per-type confidence map below.
    "IPV6_ADDRESS",
    "MAC_ADDRESS",
    "IPFS_CID",
    "YARA_RULE",
    "MITRE_TACTIC",
    "EXPLOIT_DB_ID",
    "NUCLEI_TEMPLATE",
    "COMBO_LIST_ENTRY",
    "CRYPTO_SEED_PHRASE",
})

# Per-type confidence overrides for the newer coin regexes.  The base
# _REGEX_TYPES default of 1.0 is reserved for the three original "high
# confidence" patterns (BTC/ETH/XMR).  The LTC/ZEC/DOGE/TRX/BCH/DASH
# patterns are precise (clear prefix + tight charset) and get 0.95; the
# broader XRP/SOL patterns (single-char prefix, no prefix respectively)
# get 0.85 because they rely on the crypto-context window filter; ENS
# sits in between at 0.90 (regex is tight but the value is a domain, not
# a wallet — slight additional ambiguity).
#
# Credential confidences per the design brief:
#   AWS_ACCESS_KEY  = 1.0   (AKIA + 16 alnum is unambiguous)
#   AWS_SECRET_KEY  = 0.95  (context-dependent, 40-char base64)
#   GITHUB_TOKEN    = 1.0   (gh[posaur]_ / github_pat_ are vendor-prefixed)
#   SLACK_TOKEN     = 1.0   (xox[bpas]- prefix)
#   DISCORD_TOKEN   = 0.95  (24.6.27 base64url — could collide w/ random)
#   JWT_TOKEN       = 0.85  (broader pattern, eyJ anchor only)
#   GOOGLE_API_KEY  = 1.0   (AIza + 35 chars is vendor-prefixed)
#   STRIPE_KEY      = 1.0   ([psr]k_(live|test)_ is vendor-prefixed)
#   STEALER_LOG_ENTRY = 0.90 (URL/LOGIN/PASSWORD three-line format)
#   API_KEY         = 0.80  (broad label + entropy; widest net)
_REGEX_TYPE_CONFIDENCE: dict[str, float] = {
    "BITCOIN_ADDRESS": 1.0,
    "ETHEREUM_ADDRESS": 1.0,
    "MONERO_ADDRESS": 1.0,
    "LITECOIN_ADDRESS": 0.95,
    "ZCASH_ADDRESS": 0.95,
    "DOGECOIN_ADDRESS": 0.95,
    "XRP_ADDRESS": 0.85,
    "SOLANA_ADDRESS": 0.85,
    "TRON_ADDRESS": 0.95,
    "BITCOIN_CASH_ADDRESS": 0.95,
    "DASH_ADDRESS": 0.95,
    "ENS_DOMAIN": 0.90,
    # Credential / token confidences
    "AWS_ACCESS_KEY": 1.0,
    "AWS_SECRET_KEY": 0.95,
    "GITHUB_TOKEN": 1.0,
    "SLACK_TOKEN": 1.0,
    "DISCORD_TOKEN": 0.95,
    "JWT_TOKEN": 0.85,
    "GOOGLE_API_KEY": 1.0,
    "STRIPE_KEY": 1.0,
    "STEALER_LOG_ENTRY": 0.90,
    "API_KEY": 0.80,
    # Messaging / identity handle confidences
    # Shape-specific formats (TOX_ID, SESSION_ID, MATRIX_HANDLE) are
    # unambiguous → 1.0 / 0.95.  Context-dependent ones (TELEGRAM,
    # DISCORD legacy, XMPP) use 0.85-0.90.  New-format @username,
    # Wire, Wickr, ICQ all require a context keyword → 0.85.
    "TELEGRAM_HANDLE": 0.90,
    "DISCORD_HANDLE": 0.85,
    "XMPP_JID": 0.85,
    "TOX_ID": 1.0,
    "SESSION_ID": 1.0,
    "MATRIX_HANDLE": 0.95,
    "WIRE_HANDLE": 0.85,
    "ICQ_NUMBER": 0.85,
    "WICKR_ID": 0.85,
    # Network / forensic identifier confidences (Phase 2 — final subphase)
    #   IPV6_ADDRESS     1.0  (full form is unambiguous; validator filters
    #                         private/loopback/ULA)
    #   MAC_ADDRESS      0.95 (3 input shapes; canonical uppercase colon)
    #   IPFS_CID         0.95 (CIDv0/CIDv1 are vendor-specific prefixes)
    #   YARA_RULE        0.90 (name + YARA-context check)
    #   MITRE_TACTIC     1.0  (TA0001-TA0043 is a small, fixed namespace)
    #   EXPLOIT_DB_ID    0.95 (4-6 digit ID; either EDB-ID: or URL form)
    #   NUCLEI_TEMPLATE  0.85 (broad dash-segment pattern; nuclei-context
    #                         window is the primary filter)
    #   COMBO_LIST_ENTRY 0.85 (3+ line threshold; email side only,
    #                         password never stored)
    #   CRYPTO_SEED_PHRASE 0.90 (BIP39 wordlist; canonical emit is a
    #                           marker, not the actual phrase)
    "IPV6_ADDRESS": 1.0,
    "MAC_ADDRESS": 0.95,
    "IPFS_CID": 0.95,
    "YARA_RULE": 0.90,
    "MITRE_TACTIC": 1.0,
    "EXPLOIT_DB_ID": 0.95,
    "NUCLEI_TEMPLATE": 0.85,
    "COMBO_LIST_ENTRY": 0.85,
    "CRYPTO_SEED_PHRASE": 0.90,
    # Everything else in _REGEX_TYPES stays at the default 1.0
}

_NER_TYPES: frozenset[str] = frozenset({
    "THREAT_ACTOR_HANDLE",
    "MALWARE_FAMILY",
    "RANSOMWARE_GROUP",
    "ORGANIZATION_NAME",
})


_ELEVATED_CONFIDENCE: dict[str, float] = {
    "DATE": 0.82,
    "DOMAIN": 0.82,
    "LOCATION": 0.82,
    "PERSON_NAME": 0.82,
}


def _confidence_for(entity_type: str) -> float:
    # Per-type override takes precedence — covers the newer coins whose
    # patterns are precise but slightly broader than BTC/ETH/XMR.
    if entity_type in _REGEX_TYPE_CONFIDENCE:
        return _REGEX_TYPE_CONFIDENCE[entity_type]
    if entity_type in _REGEX_TYPES:
        return 1.0
    if entity_type in _NER_TYPES:
        return 0.85
    return _ELEVATED_CONFIDENCE.get(entity_type, 0.75)


def _extraction_method_for(entity_type: str) -> str:
    if entity_type in _REGEX_TYPES:
        return "regex"
    if entity_type in _NER_TYPES:
        return "NER"
    return "LLM"


def _context_snippet(page_text: str, needle: str, max_len: int = 2000) -> str:
    """Return a window of *page_text* around *needle* for analyst / stylometry context."""
    try:
        if not page_text or not needle:
            return ""
        idx = page_text.find(needle)
        if idx < 0:
            idx = page_text.lower().find(needle.lower())
        if idx < 0:
            return ""
        half = max_len // 2
        start = max(0, idx - half)
        end = min(len(page_text), start + max_len)
        return page_text[start:end].strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Blocklist (NER / LLM only — regex types bypass; see normalize_entities)
# ---------------------------------------------------------------------------

ENTITY_BLOCKLIST: frozenset[str] = frozenset({
    "bitcoin", "btc", "ethereum", "eth", "monero", "xmr", "litecoin", "ltc",
    "dogecoin", "doge", "dash", "zcash", "zec", "ripple", "xrp", "usdt",
    "tether", "usdc", "bnb", "solana", "sol",
    "darknet", "dark web", "darkweb", "deep web", "tor", "onion",
    "marketplace", "market", "shop", "store", "vendor",
    "interface", "server", "client", "host", "system", "network",
    "database", "application", "service", "api", "endpoint",
    "stop", "start", "end", "new", "old", "free", "paid", "pro", "basic",
    "admin", "user", "root", "guest", "test", "demo",
    "h4ck3r", "h4cker", "hax0r", "haxor", "1337", "leet", "elite",
    "noob", "n00b", "script", "scriptkiddie", "skid",
    "vproxy", "proxychains", "nmap", "metasploit", "burpsuite",
    "cobalt", "covenant", "empire", "mimikatz", "lazagne", "pypykatz",
    "identities", "identity", "workflows", "workflow", "process",
    "processes", "services", "service", "systems", "system",
    "network", "networks", "access", "accounts", "account",
    "platform", "platforms", "solution", "solutions",
    "interface", "interfaces", "backend", "frontend",
    "resources", "resource", "project", "projects",
    "community", "communities", "member", "members",
    "moderator", "administrator", "operator", "staff", "support",
    "customer", "vendor", "buyer", "seller", "trader",
    "dropper", "loader", "stager", "payload", "beacon",
})

KNOWN_TOOLS: frozenset[str] = frozenset({
    "nmap", "metasploit", "cobaltstr", "cobaltstrike", "empire",
    "covenant", "brute", "hydra", "sqlmap", "nikto", "burp",
    "wireshark", "tcpdump", "netcat", "nc", "vproxy", "proxifier",
    "tor", "torbrowser", "onionbrowser", "i2p", "freenet",
    "kali", "parrot", "blackarch", "backtrack",
})

LEET_GENERIC = re.compile(r"^h[4a][ck]+[3e]?r?$")


ENTITY_MIN_LENGTH: dict[str, int] = {
    "THREAT_ACTOR_HANDLE": 4,
    "MALWARE_FAMILY": 3,
    "RANSOMWARE_GROUP": 4,
    "ORGANIZATION_NAME": 4,
    "BITCOIN_ADDRESS": 10,
    "ETHEREUM_ADDRESS": 10,
    "MONERO_ADDRESS": 10,
    "LITECOIN_ADDRESS": 10,
    "ZCASH_ADDRESS": 10,
    "DOGECOIN_ADDRESS": 10,
    "XRP_ADDRESS": 10,
    "SOLANA_ADDRESS": 10,
    "TRON_ADDRESS": 10,
    "BITCOIN_CASH_ADDRESS": 16,  # includes the "bitcoincash:" prefix
    "DASH_ADDRESS": 10,
    "ENS_DOMAIN": 5,  # "<a>.eth" minimum
    "ONION_URL": 16,
    "EMAIL_ADDRESS": 6,
    "CVE_NUMBER": 9,
    "IP_ADDRESS": 7,
    "PGP_KEY_BLOCK": 8,
    "PASTE_URL": 10,
    # Credential / token min lengths — the regexes already enforce
    # the structural shape, these floors only matter as a defence in
    # depth against a future refactor that loosens the regex.
    "AWS_ACCESS_KEY": 20,    # AKIA + 16
    "AWS_SECRET_KEY": 40,    # base64 40
    "GITHUB_TOKEN": 10,      # prefix + payload
    "SLACK_TOKEN": 20,       # xox[bpas]- + payload
    "DISCORD_TOKEN": 50,     # 24+1+6+1+27 = 59, but at least 50
    "JWT_TOKEN": 20,         # eyJ... + 2 segments
    "GOOGLE_API_KEY": 39,    # AIza + 35
    "STRIPE_KEY": 30,        # sk_live_ + 24
    "STEALER_LOG_ENTRY": 8,  # the URL string itself
    "API_KEY": 16,
    # Messaging / identity handle min lengths — these are defence-in-depth
    # floors; the regexes already enforce the shape (e.g. Telegram username
    # is 5-32 chars, Tox ID is exactly 76 hex chars).
    "TELEGRAM_HANDLE": 5,    # "lockb" (5 chars) is the shortest valid Telegram username
    "DISCORD_HANDLE": 3,     # "ab#0" technically too short for discriminator; minimum realistic: "ab#0000" (6)
    "XMPP_JID": 6,           # a@b.cd
    "TOX_ID": 76,            # exactly 76 hex chars
    "SESSION_ID": 66,        # 66 hex chars (05 + 64)
    "MATRIX_HANDLE": 5,      # @a:b.cd
    "WIRE_HANDLE": 2,        # "ab"
    "ICQ_NUMBER": 5,         # 5-digit UIN
    "WICKR_ID": 1,           # single char (rare but valid)
    # Network / forensic identifier min lengths (Phase 2 — final subphase).
    # These are defence-in-depth floors; the regexes already enforce the
    # structural shape, but the floors stop a future refactor from
    # silently allowing a too-short value through.
    "IPV6_ADDRESS": 2,         # "::" is the shortest valid form
    "MAC_ADDRESS": 17,         # "AA:BB:CC:DD:EE:FF" (17 chars including colons)
    "IPFS_CID": 46,            # Qm + 44 base58 (46 chars)
    "YARA_RULE": 3,            # 3-char minimum identifier per regex
    "MITRE_TACTIC": 6,         # "TA0001" — 6 chars
    "EXPLOIT_DB_ID": 4,        # 4-digit minimum
    "NUCLEI_TEMPLATE": 5,      # "a-b-c" minimum (3 segments)
    "COMBO_LIST_ENTRY": 5,     # "a@b.c" minimum
    "CRYPTO_SEED_PHRASE": 24,  # "SEED_PHRASE_DETECTED_12_WORDS"
}


def normalize_wallet_value(value: str) -> str:
    """Normalize wallet addresses for deduplication (Ethereum compared lowercase)."""
    value = value.strip()
    if value.startswith("0x"):
        return value.lower()
    return value


def is_blocked_entity(entity_type: str, entity_value: str) -> bool:
    """
    Returns True if an entity should be filtered as noise (NER/LLM only).
    Regex-extracted entities must not use this — their patterns are precise.
    """
    value_lower = entity_value.lower().strip()

    if value_lower in ENTITY_BLOCKLIST:
        return True

    if entity_type == "THREAT_ACTOR_HANDLE":
        if value_lower in KNOWN_TOOLS:
            return True
        if LEET_GENERIC.match(value_lower):
            return True

    min_len = ENTITY_MIN_LENGTH.get(entity_type, 3)
    if len(value_lower) < min_len:
        return True

    norm_num = value_lower.replace(".", "").replace(",", "")
    if norm_num.isnumeric():
        return True

    return False


_ORG_NOISE_RE = re.compile(
    r'\b(paid|bought|sold|hacked|leaked)\b'
    r'|\b(attempt|operations|disrupted)\b'
    r'|\b(http|onion|tor|socks)\b'
    r'|\b(zero.log|tor.native)\b'
    r'|^\d'
    r'|[<>{}\[\]|\\]',
    re.IGNORECASE,
)


def _is_valid_org_name(value: str) -> bool:
    v = value.strip()
    if len(v) < 3 or len(v) > 60:
        return False
    if len(v.split()) > 5:
        return False
    if _ORG_NOISE_RE.search(v):
        return False
    return True


# ---------------------------------------------------------------------------
# NormalizedEntity dataclass
# ---------------------------------------------------------------------------


@dataclass
class NormalizedEntity:
    entity_type: str
    value: str
    confidence: float
    source_url: str
    page_id: Optional[uuid.UUID]
    context_snippet: str = field(default="")
    extraction_method: str = field(default="")

    @property
    def canonical_value(self) -> str:
        return self.value

    def get(self, key: str, default=None):
        return getattr(self, key, default)

    def __getitem__(self, key: str):
        return getattr(self, key)


# ---------------------------------------------------------------------------
# Normalization rules per entity type
# ---------------------------------------------------------------------------


def _normalize_value(entity_type: str, value: str) -> str:
    """
    Return the canonical form of *value* for a given *entity_type*.
    Never raises — on any error returns the value stripped of leading/trailing
    whitespace.
    """
    try:
        if entity_type == "BITCOIN_ADDRESS":
            if value.lower().startswith("bc1"):
                return value.lower()
            return value

        if entity_type == "ETHEREUM_ADDRESS":
            return _eth_checksum(value)

        if entity_type == "EMAIL_ADDRESS":
            return value.lower()

        if entity_type == "CVE_NUMBER":
            return value.upper()

        if entity_type == "MITRE_TECHNIQUE":
            return value.upper()

        if entity_type in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
            return value.lower()

        if entity_type == "ONION_URL":
            try:
                from crawler.utils import normalize_url
                return normalize_url(value)
            except Exception:
                parsed_lower = value.lower()
                return parsed_lower

        stripped = value.strip()
        return re.sub(r"\s+", " ", stripped)

    except Exception:
        return value.strip()


# ---------------------------------------------------------------------------
# Web3 availability check (import once at module load)
# ---------------------------------------------------------------------------

try:
    from web3 import Web3

    Web3.to_checksum_address("0x" + "0" * 40)
    WEB3_AVAILABLE = True
except Exception:
    WEB3_AVAILABLE = False


def _eth_checksum(addr: str) -> str:
    """
    Apply EIP-55 mixed-case checksum encoding to an Ethereum address.
    Falls back to lowercase if web3 is unavailable or checksum fails.
    """
    if not addr:
        return ""

    addr = addr.strip()
    if not addr.startswith("0x") or len(addr) != 42:
        return addr.lower()

    if not WEB3_AVAILABLE:
        return addr.lower()

    try:
        from web3 import Web3

        return Web3.to_checksum_address(addr)
    except ValueError:
        return addr.lower()
    except Exception:
        return addr.lower()


def canonicalize_entity_value(entity_type: str, value: str) -> str:
    """
    Produce a canonical form of an entity value for deduplication.
    The canonical form is used as the dedup key — NOT stored as the display value.
    The original casing/formatting is preserved for display.
    """
    if not value:
        return (value or "").lower().strip()

    v = value.strip()

    if entity_type in ("THREAT_ACTOR", "MALWARE", "FORUM", "THREAT_ACTOR_HANDLE", "MALWARE_FAMILY", "RANSOMWARE_GROUP"):
        v = unicodedata.normalize("NFKD", v)
        v = v.encode("ascii", "ignore").decode("ascii")
        v = v.lower()
        v = re.sub(r"[\s\-_\.]", "", v)
        v = re.sub(r"[^\w]", "", v)
        return v

    elif entity_type in (
        "WALLET",
        "BITCOIN_ADDRESS",
        "ETHEREUM_ADDRESS",
        "MONERO_ADDRESS",
        "LITECOIN_ADDRESS",
        "ZCASH_ADDRESS",
        "DOGECOIN_ADDRESS",
        "XRP_ADDRESS",
        "SOLANA_ADDRESS",
        "TRON_ADDRESS",
        "BITCOIN_CASH_ADDRESS",
        "DASH_ADDRESS",
    ):
        if v.startswith("0x"):
            return v.lower()
        if v.startswith("4") and len(v) in (95, 106):
            return v.lower()
        if v.startswith("bitcoincash:"):
            # Lowercase the BCH prefix; cashaddr payload is already lowercase.
            return v.lower()
        if v.startswith("zs1"):
            return v.lower()
        # Solana / XRP / LTC / DOGE / TRX / DASH / ZEC: case-preserving
        # canonical forms (base58 alphabet is mixed case but addresses are
        # conventionally written in their original case to preserve the
        # implicit checksum).  We only normalize outer whitespace.
        return v.strip()

    elif entity_type == "ENS_DOMAIN":
        return v.lower().strip()

    elif entity_type in (
        # Credential / token canonicalisation — strip whitespace,
        # preserve original case (secrets are case-sensitive).  AWS
        # access keys are upper-case by format but we don't enforce
        # that here (the regex enforces it upstream).
        "AWS_ACCESS_KEY",
        "AWS_SECRET_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "DISCORD_TOKEN",
        "JWT_TOKEN",
        "GOOGLE_API_KEY",
        "STRIPE_KEY",
        "STEALER_LOG_ENTRY",
        "API_KEY",
    ):
        return v.strip()

    elif entity_type in (
        # Network / forensic identifier canonicalisation.  Most of these
        # are case-insensitive (IPv6 hex, MAC upper-cased, IPFS base58
        # / base32 which use a specific charset, MITRE tactic IDs are
        # uppercase, EDB-IDs numeric, YARA rule names case-preserved).
        # IPFS CIDs are kept as-is (base58/base32 charsets don't
        # benefit from case folding; the regex enforces the charset).
        # COMBO_LIST_ENTRY is the email side of a credential combo
        # block — same canonicalisation as EMAIL_ADDRESS.
        # CRYPTO_SEED_PHRASE is a marker string already; preserved.
        "IPV6_ADDRESS",
        "MAC_ADDRESS",
        "IPFS_CID",
        "YARA_RULE",
        "MITRE_TACTIC",
        "EXPLOIT_DB_ID",
        "NUCLEI_TEMPLATE",
        "COMBO_LIST_ENTRY",
        "CRYPTO_SEED_PHRASE",
    ):
        if entity_type == "MITRE_TACTIC":
            return v.upper().strip()
        if entity_type == "MAC_ADDRESS":
            # Canonicalise to uppercase colon form via the regex
            # helper (the extractor already does this on extraction
            # but the normaliser re-applies as defence in depth).
            from extractor.regex_patterns import _normalize_mac_address
            return _normalize_mac_address(v)
        if entity_type == "IPV6_ADDRESS":
            # Lowercase the hex (RFC 5952 recommends lowercase for
            # display) but preserve the zone-id suffix.
            base, sep, zone = v.partition("%")
            return base.lower() + (sep + zone if zone else "")
        if entity_type == "NUCLEI_TEMPLATE":
            return v.lower().strip()
        if entity_type == "COMBO_LIST_ENTRY":
            return v.lower().strip()
        return v.strip()

    elif entity_type in (
        # Messaging / identity handle canonicalisation.  Most platforms
        # treat handles as case-insensitive (Telegram, Discord, Wire,
        # Wickr, Matrix, XMPP) so we lowercase.  TOX_ID is always uppercase
        # hex by convention.  SESSION_ID is always lowercase.  ICQ number
        # is numeric and stays as-is.
        "TELEGRAM_HANDLE",
        "DISCORD_HANDLE",
        "XMPP_JID",
        "MATRIX_HANDLE",
        "WIRE_HANDLE",
        "WICKR_ID",
        "TOX_ID",
        "SESSION_ID",
        "ICQ_NUMBER",
    ):
        if entity_type == "TOX_ID":
            return v.upper().strip()
        if entity_type == "ICQ_NUMBER":
            return v.strip()
        return v.lower().strip()

    elif entity_type in ("CVE", "CVE_NUMBER"):
        v = v.upper().strip()
        v = re.sub(r"\s+", "-", v)
        return v

    elif entity_type in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
        return v.lower()

    elif entity_type == "MITRE_TECHNIQUE":
        return v.upper().strip()

    elif entity_type in ("EMAIL", "EMAIL_ADDRESS"):
        return v.lower().strip()

    elif entity_type == "ONION_URL":
        v = v.lower().rstrip("/")
        v = re.sub(r"^https://", "http://", v)
        return v

    elif entity_type in ("PGP_KEY", "PGP_KEY_BLOCK"):
        normalized = re.sub(r"\s+", "", v).upper()
        return "pgp:" + hashlib.sha256(normalized.encode()).hexdigest()

    else:
        v = v.lower().strip()

    return v[:1024]


def are_same_entity(type_a: str, value_a: str, type_b: str, value_b: str) -> bool:
    """Returns True if two entities should be considered the same."""
    if type_a != type_b:
        return False
    return canonicalize_entity_value(type_a, value_a) == canonicalize_entity_value(type_b, value_b)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def normalize_entities(
    raw_entities: dict[str, list[str]],
    page_url: str,
    page_id: Optional[uuid.UUID] = None,
    page_text: Optional[str] = None,
) -> list[NormalizedEntity]:
    """
    Convert raw extraction results into deduplicated NormalizedEntity records.
    """
    seen_values: set[str] = set()
    result: list[NormalizedEntity] = []

    tool_count = 0
    generic_count = 0
    leet_count = 0
    noise_count = 0

    for entity_type, values in raw_entities.items():
        confidence = _confidence_for(entity_type)
        for raw_value in values:
            if not raw_value or not raw_value.strip():
                continue

            if entity_type in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
                if not _validate_hash_length(entity_type, raw_value):
                    logger.debug(
                        f"Hash length validation failed for {entity_type}={raw_value}"
                    )
                    continue

            if entity_type == "ONION_URL":
                if not _validate_onion_url(raw_value):
                    logger.debug("ONION_URL discarded (not a valid onion address): %r", raw_value)
                    continue

            # Defensive shape check for the new crypto wallet types.  The
            # extractor already enforces these shapes via regex + validators;
            # this is a second line of defence so a malformed value can
            # never reach the DB even if a future refactor weakens the regex.
            _CRYPTO_WALLET_TYPES = (
                "LITECOIN_ADDRESS",
                "ZCASH_ADDRESS",
                "DOGECOIN_ADDRESS",
                "XRP_ADDRESS",
                "SOLANA_ADDRESS",
                "TRON_ADDRESS",
                "BITCOIN_CASH_ADDRESS",
                "DASH_ADDRESS",
                "ENS_DOMAIN",
            )
            if entity_type in _CRYPTO_WALLET_TYPES:
                if not _validate_crypto_wallet(entity_type, raw_value):
                    logger.debug(
                        "Crypto wallet validation failed for %s=%r",
                        entity_type,
                        raw_value,
                    )
                    continue

            # Defensive shape check for the network / forensic
            # identifier types added in Phase 2 (final subphase).  The
            # extractors already enforce these shapes; this is a
            # second line of defence so a malformed value can never
            # reach the DB even if a future refactor weakens the regex.
            _NETWORK_FORENSIC_TYPES = (
                "IPV6_ADDRESS",
                "MAC_ADDRESS",
                "IPFS_CID",
                "YARA_RULE",
                "MITRE_TACTIC",
                "EXPLOIT_DB_ID",
                "NUCLEI_TEMPLATE",
                "COMBO_LIST_ENTRY",
                "CRYPTO_SEED_PHRASE",
            )
            if entity_type in _NETWORK_FORENSIC_TYPES:
                if not _validate_network_forensic(entity_type, raw_value):
                    logger.debug(
                        "Network/forensic validation failed for %s=%r",
                        entity_type,
                        raw_value,
                    )
                    continue

            canonical = _normalize_value(entity_type, raw_value)
            if not canonical:
                continue

            if entity_type not in _REGEX_TYPES:
                value_lower = canonical.lower()
                if is_blocked_entity(entity_type, canonical):
                    if entity_type == "THREAT_ACTOR_HANDLE" and value_lower in KNOWN_TOOLS:
                        tool_count += 1
                    elif entity_type == "THREAT_ACTOR_HANDLE" and LEET_GENERIC.match(value_lower):
                        leet_count += 1
                    elif value_lower in ENTITY_BLOCKLIST:
                        generic_count += 1
                    else:
                        noise_count += 1

                    logger.debug(
                        "Filtered blocked entity: %s=%s", entity_type, canonical
                    )
                    continue

                if entity_type == "ORGANIZATION_NAME" and not _is_valid_org_name(canonical):
                    noise_count += 1
                    logger.debug("Filtered noisy ORGANIZATION_NAME: %s", canonical)
                    continue

            dedup_key = f"{entity_type}::{canonical}"
            if dedup_key in seen_values:
                continue
            seen_values.add(dedup_key)
            snip = _context_snippet(page_text, canonical) if page_text else ""
            result.append(
                NormalizedEntity(
                    entity_type=entity_type,
                    value=canonical,
                    confidence=confidence,
                    source_url=page_url,
                    page_id=page_id,
                    context_snippet=snip,
                    extraction_method=_extraction_method_for(entity_type),
                )
            )

    total_filtered = tool_count + leet_count + generic_count + noise_count
    if total_filtered:
        logger.warning(
            f"Entity blocklist filtered {total_filtered} entities "
            f"(tool_names={tool_count}, generic_terms={generic_count}, "
            f"leet_generic={leet_count}, NER/LLM noise={noise_count})"
        )

    return result


def merge_with_db(
    entities: list[NormalizedEntity],
    investigation_id: Optional[uuid.UUID] = None,
) -> list:
    """
    Upsert each entity to the DB entities table using canonical deduplication.
    Returns a list of DB-assigned entity IDs (as strings).
    """
    if not os.getenv("DATABASE_URL"):
        logger.warning(
            "DATABASE_URL not set — skipping DB persist (%d entities)", len(entities)
        )
        return []

    if not entities:
        return []

    ids: list = []
    new_count = 0
    dedup_count = 0

    try:
        from db.session import get_session
        from db.queries import upsert_entity_canonical, create_page, get_page_by_url

        with get_session() as session:
            page_cache: dict[str, object] = {}

            for entity in entities:
                url = entity.source_url
                if url not in page_cache:
                    page = get_page_by_url(session, url)
                    if page is None:
                        page = create_page(session, url=url)
                    page_cache[url] = page

                page = page_cache[url]

                db_entity, created = upsert_entity_canonical(
                    session=session,
                    investigation_id=investigation_id,
                    entity_type=entity.entity_type,
                    entity_value=entity.value,
                    confidence=entity.confidence,
                    source_page_id=page.id,
                    context_snippet=entity.context_snippet,
                    extraction_method=entity.extraction_method or None,
                )

                if created:
                    new_count += 1
                else:
                    dedup_count += 1

                ids.append(str(db_entity.id))

            session.commit()
            if investigation_id:
                logger.warning(
                    f"[{investigation_id}] Entity dedup: {new_count} new, {dedup_count} merged with existing"
                )

    except Exception as exc:
        logger.warning("merge_with_db failed: %s", exc)
        return []

    return ids
