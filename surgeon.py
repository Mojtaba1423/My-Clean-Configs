# surgeon.py
# -*- coding: utf-8 -*-

"""
MOJTABA Surgeon V7.4
- Keeps external contract stable:
  - main file: surgeon.py
  - output: MOJTABA_CLEAN_LIST.txt
  - telemetry: surgeon_telemetry.json
- Internal logic rebuilt to be stricter:
  1) Fetch sources
  2) Extract vless:// links
  3) Parse strictly
  4) Hard offline filtering
  5) Deduplicate
  6) Live test ALL deduped candidates via Go prober (TCP connect only)
  7) Final scoring mainly from live results
  8) Rank + cap to 128
"""

from __future__ import annotations

import base64
import json
import math
import os
import re
import socket
import statistics
import subprocess
import time
import uuid as uuidlib

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlsplit

import requests


VERSION = "7.4"
OUTPUT_FILE = "MOJTABA_CLEAN_LIST.txt"
TELEMETRY_FILE = "surgeon_telemetry.json"

MAX_OUTPUT = 128
MAX_PER_HOST = 2

REQUIRED_SECURITY = "reality"
REQUIRED_TYPE = "tcp"
REQUIRED_FP = "chrome"

# Only accept these ports
GOLDEN_PORTS = {443, 2053, 2083, 8443}

# Live probe settings
LIVE_TEST_BINARY = os.environ.get("LIVE_TEST_BINARY", "./prober")
LIVE_TEST_CONCURRENCY = int(os.environ.get("LIVE_TEST_CONCURRENCY", "400"))
LIVE_TEST_TIMEOUT_MS = int(os.environ.get("LIVE_TEST_TIMEOUT_MS", "2500"))
LIVE_TEST_PROCESS_TIMEOUT_SEC = int(os.environ.get("LIVE_TEST_PROCESS_TIMEOUT_SEC", "180"))

# Source fetch settings
FETCH_CONNECT_TIMEOUT = 12
FETCH_READ_TIMEOUT = 20
USER_AGENT = f"Mozilla/5.0 (MOJTABA-Surgeon/{VERSION})"

# Keep your current real sources here.
# IMPORTANT: Replace placeholders below with your actual source list.
SOURCES = [
    # "https://example1.txt",
    # "https://example2.txt",
]

# Optional future add-ons; does not erase your main SOURCES list
EXTRA_SOURCES = []

ALL_SOURCES = SOURCES + [s for s in EXTRA_SOURCES if s not in SOURCES]

SOURCE_BONUS = {
    # Example:
    # "https://example1.txt": 4.0,
}

DARK_WORDS = [
    "NIGHT", "DARK", "SHADOW", "BLACK", "MOON", "VOID",
    "GHOST", "SILENT", "DUSK", "RAVEN", "WOLF", "STEALTH",
]

VLESS_RE = re.compile(r"vless://[^\s\"\'<>\)\]]+", re.IGNORECASE)
B64_CLEAN_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s\r\n]+$")

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class Candidate:
    raw_url: str
    source: str
    uuid: str
    host: str
    port: int
    query: Dict[str, str]
    tag: str

    offline_score: float = 0.0
    dedupe_key: str = ""

    tcp_ok: bool = False
    latency_ms: Optional[float] = None
    live_score: float = 0.0
    total_score: float = 0.0
    live_error: str = ""

    normalized_url: str = ""


@dataclass
class Telemetry:
    version: str = VERSION
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    source_stats: Dict[str, dict] = field(default_factory=dict)

    total_extracted_links: int = 0
    total_parsed_links: int = 0

    rejects: Counter = field(default_factory=Counter)

    valid_candidates_before_dedupe: int = 0
    deduped_candidates: int = 0

    live_probe_enabled: bool = True
    live_probe_binary_exists: bool = False
    live_probe_invoked: bool = False
    live_probe_succeeded: bool = False
    live_probe_failed_reason: str = ""

    live_total_tested: int = 0
    live_success: int = 0
    live_fail: int = 0
    live_latency_min_ms: Optional[float] = None
    live_latency_avg_ms: Optional[float] = None
    live_latency_p50_ms: Optional[float] = None
    live_latency_p90_ms: Optional[float] = None
    live_latency_max_ms: Optional[float] = None

    final_selected: int = 0


def now_iso_like() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def maybe_decode_base64_text(text: str) -> str:
    if not text or "vless://" in text.lower():
        return text

    sample = text.strip()
    if len(sample) < 16:
        return text
    if not B64_CLEAN_RE.match(sample):
        return text

    compact = "".join(sample.split())
    paddings = ["", "=", "==", "==="]

    for alt in (compact, compact.replace("-", "+").replace("_", "/")):
        for pad in paddings:
            try:
                decoded = base64.b64decode(alt + pad, validate=False)
                decoded_text = decoded.decode("utf-8", errors="ignore")
                if "vless://" in decoded_text.lower():
                    return decoded_text
            except Exception:
                pass

    return text


def safe_get_single(query_map: Dict[str, List[str]], key: str) -> str:
    vals = query_map.get(key, [])
    if not vals:
        return ""
    return vals[0].strip()


def is_valid_uuid(val: str) -> bool:
    try:
        uuidlib.UUID(val)
        return True
    except Exception:
        return False


def is_ip_literal(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except Exception:
        return False


def is_private_or_bogon_ip(host: str) -> bool:
    try:
        ip = ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_link_local
        )
    except Exception:
        return False


def is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if host.lower() == "localhost":
        return False
    return bool(HOSTNAME_RE.match(host))


def normalize_host(host: str) -> str:
    return host.strip().strip(".").lower()


def normalize_tag(tag: str) -> str:
    tag = unquote(tag or "").strip()
    tag = re.sub(r"\s+", " ", tag)
    tag = re.sub(r"[^\w\-\.\s|]+", "", tag, flags=re.UNICODE)
    tag = tag[:80].strip()
    return tag or "NO_TAG"


def looks_like_hex(s: str, min_len: int = 6) -> bool:
    s = (s or "").strip()
    return len(s) >= min_len and bool(HEX_RE.fullmatch(s))


def choose_sni(q: Dict[str, str]) -> str:
    return normalize_host(q.get("sni") or q.get("servername") or q.get("serverName") or "")


def source_bonus(source: str) -> float:
    return float(SOURCE_BONUS.get(source, 0.0))


def maybe_dark_word(seed: str) -> str:
    if not seed:
        return DARK_WORDS[0]
    idx = sum(ord(c) for c in seed) % len(DARK_WORDS)
    return DARK_WORDS[idx]


def compute_offline_score(source: str, host: str, port: int, q: Dict[str, str], tag: str) -> float:
    score = 0.0

    if port == 443:
        score += 18
    elif port in {2053, 2083, 8443}:
        score += 12

    sni = choose_sni(q)
    if sni and not is_ip_literal(sni):
        score += 10

    host_l = host.lower()
    sni_l = sni.lower()

    if host_l == sni_l and sni_l:
        score += 7

    pbk = q.get("pbk", "")
    if pbk and len(pbk) >= 20:
        score += 9

    sid = q.get("sid", "")
    if sid and 0 < len(sid) <= 32:
        score += 5

    spx = q.get("spx", "")
    if spx:
        score += 2

    if q.get("fp", "").lower() == REQUIRED_FP:
        score += 6

    if tag and tag != "NO_TAG":
        score += 1.5

    score += source_bonus(source)

    # Small hostname quality hint
    if "." in host_l and not is_ip_literal(host_l):
        score += 3

    return score


def make_dedupe_key(uuid: str, host: str, port: int, q: Dict[str, str]) -> str:
    sni = choose_sni(q)
    pbk = q.get("pbk", "").strip()
    sid = q.get("sid", "").strip()
    fp = q.get("fp", "").strip().lower()
    return f"{uuid}|{host}|{port}|{sni}|{pbk}|{sid}|{fp}"


def build_normalized_url(c: Candidate) -> str:
    q = dict(c.query)

    ordered_keys = [
        "encryption",
        "security",
        "type",
        "fp",
        "sni",
        "pbk",
        "sid",
        "spx",
        "flow",
        "alpn",
    ]

    # preserve any extra query items after preferred keys
    final_pairs = []

    if "encryption" not in q:
        q["encryption"] = "none"

    if "sni" not in q:
        sn = choose_sni(q)
        if sn:
            q["sni"] = sn

    used = set()
    for k in ordered_keys:
        if k in q and q[k] != "":
            final_pairs.append((k, q[k]))
            used.add(k)

    for k in sorted(q.keys()):
        if k not in used and q[k] != "":
            final_pairs.append((k, q[k]))

    query_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in final_pairs)
    return f"vless://{c.uuid}@{c.host}:{c.port}?{query_str}#{quote(c.tag, safe='| -._')}"


def fetch_source(url: str, tel: Telemetry) -> str:
    st = {
        "url": url,
        "ok": False,
        "status_code": None,
        "error": "",
        "bytes": 0,
        "extracted_links": 0,
    }

    try:
        r = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=(FETCH_CONNECT_TIMEOUT, FETCH_READ_TIMEOUT),
        )
        st["status_code"] = r.status_code
        body = r.text or ""
        st["bytes"] = len(body.encode("utf-8", errors="ignore"))

        if r.status_code != 200:
            tel.source_stats[url] = st
            return ""

        body = maybe_decode_base64_text(body)
        st["ok"] = True
        tel.source_stats[url] = st
        return body
    except Exception as e:
        st["error"] = str(e)
        tel.source_stats[url] = st
        return ""


def extract_vless_links(text: str) -> List[str]:
    if not text:
        return []

    found = VLESS_RE.findall(text)
    if not found:
        decoded = maybe_decode_base64_text(text)
        if decoded != text:
            found = VLESS_RE.findall(decoded)

    cleaned = []
    for x in found:
        x = x.strip().strip('\'"')
        x = x.rstrip(">,;")
        cleaned.append(x)
    return cleaned


def parse_candidate(raw_url: str, source: str, tel: Telemetry) -> Optional[Candidate]:
    tel.total_parsed_links += 1

    try:
        u = urlsplit(raw_url)
    except Exception:
        tel.rejects["bad_urlsplit"] += 1
        return None

    if u.scheme.lower() != "vless":
        tel.rejects["scheme_not_vless"] += 1
        return None

    if "@" not in u.netloc:
        tel.rejects["missing_at"] += 1
        return None

    userinfo, hostport = u.netloc.rsplit("@", 1)
    userinfo = userinfo.strip()
    if not is_valid_uuid(userinfo):
        tel.rejects["bad_uuid"] += 1
        return None

    if ":" not in hostport:
        tel.rejects["missing_port"] += 1
        return None

    host_raw, port_raw = hostport.rsplit(":", 1)
    host = normalize_host(host_raw)

    if not host:
        tel.rejects["empty_host"] += 1
        return None

    try:
        port = int(port_raw)
    except Exception:
        tel.rejects["bad_port"] += 1
        return None

    if port not in GOLDEN_PORTS:
        tel.rejects["port_not_allowed"] += 1
        return None

    if is_ip_literal(host):
        if is_private_or_bogon_ip(host):
            tel.rejects["private_or_bogon_host_ip"] += 1
            return None
    else:
        if not is_valid_hostname(host):
            tel.rejects["bad_hostname"] += 1
            return None

    qmap = parse_qs(u.query, keep_blank_values=True)

    q = {}
    for k in qmap:
        q[k] = safe_get_single(qmap, k)

    if q.get("security", "").lower() != REQUIRED_SECURITY:
        tel.rejects["security_not_reality"] += 1
        return None

    if q.get("type", "").lower() != REQUIRED_TYPE:
        tel.rejects["type_not_tcp"] += 1
        return None

    if q.get("fp", "").lower() != REQUIRED_FP:
        tel.rejects["fp_not_chrome"] += 1
        return None

    pbk = q.get("pbk", "").strip()
    if not pbk or len(pbk) < 20:
        tel.rejects["missing_or_short_pbk"] += 1
        return None

    sni = choose_sni(q)
    if not sni:
        tel.rejects["missing_sni"] += 1
        return None

    if is_ip_literal(sni):
        if is_private_or_bogon_ip(sni):
            tel.rejects["private_or_bogon_sni_ip"] += 1
            return None
    else:
        if not is_valid_hostname(sni):
            tel.rejects["bad_sni"] += 1
            return None

    sid = q.get("sid", "").strip()
    if sid and len(sid) > 64:
        tel.rejects["sid_too_long"] += 1
        return None

    flow = q.get("flow", "").strip().lower()
    if flow and flow not in {"", "xtls-rprx-vision"}:
        tel.rejects["unsupported_flow"] += 1
        return None

    encryption = q.get("encryption", "").strip().lower()
    if encryption and encryption != "none":
        tel.rejects["bad_encryption"] += 1
        return None

    tag = normalize_tag(u.fragment or "")
    offline_score = compute_offline_score(source, host, port, q, tag)
    dedupe_key = make_dedupe_key(userinfo, host, port, q)

    c = Candidate(
        raw_url=raw_url,
        source=source,
        uuid=userinfo,
        host=host,
        port=port,
        query=q,
        tag=tag,
        offline_score=offline_score,
        dedupe_key=dedupe_key,
    )
    c.normalized_url = build_normalized_url(c)
    return c


def dedupe_candidates(candidates: List[Candidate]) -> List[Candidate]:
    best_by_key: Dict[str, Candidate] = {}

    for c in candidates:
        prev = best_by_key.get(c.dedupe_key)
        if prev is None:
            best_by_key[c.dedupe_key] = c
            continue

        # Prefer higher offline score; tie-break shorter normalized URL
        if c.offline_score > prev.offline_score:
            best_by_key[c.dedupe_key] = c
        elif c.offline_score == prev.offline_score:
            if len(c.normalized_url) < len(prev.normalized_url):
                best_by_key[c.dedupe_key] = c

    return list(best_by_key.values())


def run_go_live_probe(candidates: List[Candidate], tel: Telemetry) -> Dict[str, dict]:
    tel.live_probe_binary_exists = os.path.isfile(LIVE_TEST_BINARY) and os.access(LIVE_TEST_BINARY, os.X_OK)
    if not tel.live_probe_binary_exists:
        tel.live_probe_succeeded = False
        tel.live_probe_failed_reason = f"binary_not_found_or_not_executable: {LIVE_TEST_BINARY}"
        return {}

    payload = {
        "concurrency": LIVE_TEST_CONCURRENCY,
        "timeout_ms": LIVE_TEST_TIMEOUT_MS,
        "targets": [
            {
                "id": c.dedupe_key,
                "host": c.host,
                "port": c.port,
            }
            for c in candidates
        ],
    }

    try:
        tel.live_probe_invoked = True
        proc = subprocess.run(
            [LIVE_TEST_BINARY],
            input=json.dumps(payload).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=LIVE_TEST_PROCESS_TIMEOUT_SEC,
            check=False,
        )

        if proc.returncode != 0:
            tel.live_probe_succeeded = False
            tel.live_probe_failed_reason = f"prober_exit_{proc.returncode}: {proc.stderr.decode('utf-8', errors='ignore')[:500]}"
            return {}

        out = proc.stdout.decode("utf-8", errors="ignore").strip()
        data = json.loads(out)
        tel.live_probe_succeeded = True

        results = {}
        for item in data.get("results", []):
            rid = str(item.get("id", "")).strip()
            if rid:
                results[rid] = item
        return results

    except subprocess.TimeoutExpired:
        tel.live_probe_succeeded = False
        tel.live_probe_failed_reason = "prober_timeout"
        return {}
    except Exception as e:
        tel.live_probe_succeeded = False
        tel.live_probe_failed_reason = f"prober_exception: {e}"
        return {}


def compute_live_score(tcp_ok: bool, latency_ms: Optional[float]) -> float:
    if not tcp_ok:
        return 0.0

    base = 100.0

    if latency_ms is None:
        return 70.0

    x = float(latency_ms)

    if x <= 120:
        bonus = 38
    elif x <= 180:
        bonus = 30
    elif x <= 250:
        bonus = 22
    elif x <= 400:
        bonus = 14
    elif x <= 700:
        bonus = 7
    elif x <= 1200:
        bonus = 2
    else:
        bonus = -8

    return max(10.0, base + bonus)


def merge_live_probe_scores(candidates: List[Candidate], results: Dict[str, dict], tel: Telemetry) -> None:
    latencies = []

    for c in candidates:
        item = results.get(c.dedupe_key)
        if not item:
            c.tcp_ok = False
            c.latency_ms = None
            c.live_error = "missing_result"
            c.live_score = 0.0
            continue

        c.tcp_ok = bool(item.get("tcp_ok", False))
        lat = item.get("latency_ms", None)
        c.latency_ms = float(lat) if isinstance(lat, (int, float)) else None
        c.live_error = str(item.get("error", "") or "")
        c.live_score = compute_live_score(c.tcp_ok, c.latency_ms)

        tel.live_total_tested += 1
        if c.tcp_ok:
            tel.live_success += 1
            if c.latency_ms is not None:
                latencies.append(c.latency_ms)
        else:
            tel.live_fail += 1

    if latencies:
        latencies_sorted = sorted(latencies)
        tel.live_latency_min_ms = round(latencies_sorted[0], 2)
        tel.live_latency_avg_ms = round(sum(latencies_sorted) / len(latencies_sorted), 2)
        tel.live_latency_p50_ms = round(percentile(latencies_sorted, 50), 2)
        tel.live_latency_p90_ms = round(percentile(latencies_sorted, 90), 2)
        tel.live_latency_max_ms = round(latencies_sorted[-1], 2)


def percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[f] * (c - k)
    d1 = sorted_vals[c] * (k - f)
    return d0 + d1


def assign_total_scores(candidates: List[Candidate], live_worked: bool) -> None:
    for c in candidates:
        if live_worked:
            # live is the main ranking signal, offline just a tiebreak helper
            c.total_score = (c.live_score * 1.0) + (c.offline_score * 0.20)
        else:
            # safe fallback if prober is unavailable/broken
            c.total_score = c.offline_score


def final_select(candidates: List[Candidate]) -> List[Candidate]:
    # Prefer tcp_ok if live worked and scores already reflect that.
    ordered = sorted(
        candidates,
        key=lambda c: (
            c.total_score,
            1 if c.tcp_ok else 0,
            -(c.latency_ms if c.latency_ms is not None else 999999),
            c.offline_score,
            -len(c.tag or ""),
        ),
        reverse=True,
    )

    chosen = []
    per_host = defaultdict(int)

    for c in ordered:
        if len(chosen) >= MAX_OUTPUT:
            break
        if per_host[c.host] >= MAX_PER_HOST:
            continue
        chosen.append(c)
        per_host[c.host] += 1

    return chosen


def make_final_tag(c: Candidate, rank: int) -> str:
    sni = choose_sni(c.query)
    dark = maybe_dark_word(c.host + sni + c.tag)
    live_part = "LIVE" if c.tcp_ok else "COLD"
    lat_part = f"{int(c.latency_ms)}MS" if c.latency_ms is not None else "N/A"
    return f"MOJTABA | {dark} | {live_part} | {lat_part} | {c.host}:{c.port} | R{rank}"[:120]


def rewrite_with_final_tag(c: Candidate, rank: int) -> str:
    old_tag = c.tag
    c.tag = make_final_tag(c, rank)
    try:
        return build_normalized_url(c)
    finally:
        c.tag = old_tag


def write_output(selected: List[Candidate]) -> None:
    lines = []
    for idx, c in enumerate(selected, 1):
        lines.append(rewrite_with_final_tag(c, idx))
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines).strip() + ("\n" if lines else ""))


def write_telemetry(tel: Telemetry) -> None:
    tel.finished_at = time.time()

    payload = {
        "version": tel.version,
        "started_at": tel.started_at,
        "finished_at": tel.finished_at,
        "duration_sec": round(tel.finished_at - tel.started_at, 3),
        "started_at_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tel.started_at)),
        "finished_at_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tel.finished_at)),
        "source_stats": tel.source_stats,
        "total_extracted_links": tel.total_extracted_links,
        "total_parsed_links": tel.total_parsed_links,
        "rejects": dict(tel.rejects),
        "valid_candidates_before_dedupe": tel.valid_candidates_before_dedupe,
        "deduped_candidates": tel.deduped_candidates,
        "live_probe": {
            "enabled": tel.live_probe_enabled,
            "binary_exists": tel.live_probe_binary_exists,
            "invoked": tel.live_probe_invoked,
            "succeeded": tel.live_probe_succeeded,
            "failed_reason": tel.live_probe_failed_reason,
            "total_tested": tel.live_total_tested,
            "success": tel.live_success,
            "fail": tel.live_fail,
            "latency": {
                "min_ms": tel.live_latency_min_ms,
                "avg_ms": tel.live_latency_avg_ms,
                "p50_ms": tel.live_latency_p50_ms,
                "p90_ms": tel.live_latency_p90_ms,
                "max_ms": tel.live_latency_max_ms,
            },
        },
        "final_selected": tel.final_selected,
    }

    with open(TELEMETRY_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def fallback_minimal_outputs_if_needed():
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
            f.write("")
    if not os.path.exists(TELEMETRY_FILE):
        with open(TELEMETRY_FILE, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"version": VERSION, "note": "fallback_created"}, f, ensure_ascii=False, indent=2)


def main():
    tel = Telemetry()

    try:
        all_links: List[str] = []
        parsed_candidates: List[Candidate] = []

        for src in ALL_SOURCES:
            body = fetch_source(src, tel)
            links = extract_vless_links(body)
            tel.total_extracted_links += len(links)

            if src not in tel.source_stats:
                tel.source_stats[src] = {
                    "url": src,
                    "ok": False,
                    "status_code": None,
                    "error": "",
                    "bytes": 0,
                    "extracted_links": len(links),
                }
            else:
                tel.source_stats[src]["extracted_links"] = len(links)

            all_links.extend((x, src) for x in links)

        for raw_url, src in all_links:
            c = parse_candidate(raw_url, src, tel)
            if c is not None:
                parsed_candidates.append(c)

        tel.valid_candidates_before_dedupe = len(parsed_candidates)

        deduped = dedupe_candidates(parsed_candidates)
        tel.deduped_candidates = len(deduped)

        live_results = run_go_live_probe(deduped, tel)
        merge_live_probe_scores(deduped, live_results, tel)
        assign_total_scores(deduped, live_worked=tel.live_probe_succeeded)

        selected = final_select(deduped)
        tel.final_selected = len(selected)

        write_output(selected)
        write_telemetry(tel)

        print(f"[{now_iso_like()}] Surgeon V{VERSION} done")
        print(f"Sources: {len(ALL_SOURCES)}")
        print(f"Extracted: {tel.total_extracted_links}")
        print(f"Valid before dedupe: {tel.valid_candidates_before_dedupe}")
        print(f"Deduped: {tel.deduped_candidates}")
        print(f"Live probe succeeded: {tel.live_probe_succeeded}")
        print(f"Final selected: {tel.final_selected}")

    except Exception as e:
        tel.live_probe_failed_reason = f"fatal_exception: {e}"
        try:
            write_telemetry(tel)
        except Exception:
            pass
        fallback_minimal_outputs_if_needed()
        raise


if __name__ == "__main__":
    main()
