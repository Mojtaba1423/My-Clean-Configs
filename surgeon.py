# -*- coding: utf-8 -*-

"""
MOJTABA Surgeon V7.6 (Safe Stability/Diversity Rebuild)

External contract:
  - main file: surgeon.py
  - output: MOJTABA_CLEAN_LIST.txt
  - telemetry: surgeon_telemetry.json

Goals:
  1) Keep GitHub Actions light and fast
  2) Keep Go prober as the live-test engine
  3) Rank by general stability, not one-shot luck
  4) Reduce cluster dominance with diversity-aware selection
  5) Keep only a single final output file
  6) Preserve Mojtaba naming tiers by final rank
"""

from __future__ import annotations

import base64
import json
import math
import os
import re
import subprocess
import time
import uuid as uuidlib

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlsplit

import requests


VERSION = "7.6"

OUTPUT_FILE = "MOJTABA_CLEAN_LIST.txt"
TELEMETRY_FILE = "surgeon_telemetry.json"

MAX_OUTPUT = int(os.environ.get("MAX_OUTPUT", "128"))

MAX_PER_HOST = int(os.environ.get("MAX_PER_HOST", "2"))
MAX_PER_SNI = int(os.environ.get("MAX_PER_SNI", "3"))
MAX_PER_FP = int(os.environ.get("MAX_PER_FP", "16"))
MAX_PER_PORT = int(os.environ.get("MAX_PER_PORT", "64"))
MAX_PER_FAMILY = int(os.environ.get("MAX_PER_FAMILY", "2"))

REQUIRED_SECURITY = "reality"
REQUIRED_TYPE = "tcp"
REQUIRED_FP = "chrome"

GOLDEN_PORTS = {443, 2053, 2083, 8443}

LIVE_TEST_BINARY = os.environ.get("LIVE_TEST_BINARY", "./prober")
LIVE_TEST_CONCURRENCY = int(os.environ.get("LIVE_TEST_CONCURRENCY", "400"))
LIVE_TEST_TIMEOUT_MS = int(os.environ.get("LIVE_TEST_TIMEOUT_MS", "2500"))
LIVE_TEST_PROCESS_TIMEOUT_SEC = int(os.environ.get("LIVE_TEST_PROCESS_TIMEOUT_SEC", "180"))

LIVE_TEST_ATTEMPTS = int(os.environ.get("LIVE_TEST_ATTEMPTS", "1"))
LIVE_TEST_TCP_ATTEMPTS = int(os.environ.get("LIVE_TEST_TCP_ATTEMPTS", "0"))
LIVE_TEST_TLS_ATTEMPTS = int(os.environ.get("LIVE_TEST_TLS_ATTEMPTS", "0"))
LIVE_TEST_ATTEMPT_PAUSE_MS = int(os.environ.get("LIVE_TEST_ATTEMPT_PAUSE_MS", "0"))

FETCH_CONNECT_TIMEOUT os.environ.get("FETCH_CONNECT_TIMEOUT", "12"))
FETCH_READ_TIMEOUT os.environ.get("FETCH_READ_TIMEOUT", "20"))

USER_AGENT = f"Mozilla/5.0 (MOJTABA-Surgeon/{VERSION})"

TOP_NAME_COUNT = int(os.environ.get("TOP_NAME_COUNT", "5"))
MIDDLE_NAME_UNTIL = int(os.environ.get("MIDDLE_NAME_UNTIL", "32"))

NAME_TOP = "🕯️🖤 Mojtaba1423"
NAME_MIDDLE = "🌙⚫ @mojtaba_1423"
NAME_REST = "🦂🌑 M_1423"

SOURCES = [
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/mrvcoder/V2rayCollector/refs/heads/main/vless_iran.txt",
    "https://raw.githubusercontent.com/jafarm83/ConfigV2Ray/refs/heads/main/jafar_ultimate.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/refs/heads/main/main/vless.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/refs/heads/main/Configs/VLESS-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no1.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no2.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no3.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no4.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no5.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no6.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no7.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no8.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no9.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no10.txt",
]

EXTRA_SOURCES = []

SOURCE_BONUS = {}

VLESS_RE = re.compile(r"vless://[^\s\"\'<>\\)\\]]+", re.IGNORECASE)
B64_CLEAN_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s\r\n]+$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def unique_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for item in items:
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


ALL_SOURCES = unique_preserve_order(SOURCES + [s for s in EXTRA_SOURCES if s not in SOURCES])


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
    family_key: str = ""

    tcp_ok: bool = False
    tcp_latency_ms: Optional[float] = None

    tls_ok: bool = False
    tls_latency_ms: Optional[float] = None

    live_score: float = 0.0
    total_score: float = 0.0
    selection_score: float = 0.0

    live_error: str = ""
    tls_error: str = ""

    tcp_attempts: int = 0
    tcp_successes: int = 0
    tls_attempts: int = 0
    tls_successes: int = 0

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
    live_probe_tls_supported: bool = False

    live_total_tested: int = 0

    live_tcp_success: int = 0
    live_tcp_fail: int = 0
    live_tcp_latency_min_ms: Optional[float] = None
    live_tcp_latency_avg_ms: Optional[float] = None
    live_tcp_latency_p50_ms: Optional[float] = None
    live_tcp_latency_p90_ms: Optional[float] = None
    live_tcp_latency_max_ms: Optional[float] = None

    live_tls_success: int = 0
    live_tls_fail: int = 0
    live_tls_latency_min_ms: Optional[float] = None
    live_tls_latency_avg_ms: Optional[float] = None
    live_tls_latency_p50_ms: Optional[float] = None
    live_tls_latency_p90_ms: Optional[float] = None
    live_tls_latency_max_ms: Optional[float] = None

    selected_unique_hosts: int = 0
    selected_unique_sni: int = 0
    selected_unique_fp: int = 0
    selected_unique_ports: int = 0
    selected_unique_families: int = 0
    selected_top_family_share: float = 0.0

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
    tag = re.sub(r"[^\w\-\.\s|@]+", "", tag, flags=re.UNICODE)
    tag = tag[:80].strip()
    return tag or "NO_TAG"


def looks_like_hex(s: str, min_len: int = 6) -> bool:
    s = (s or "").strip()
    return len(s) >= min_len and bool(HEX_RE.fullmatch(s))


def choose_sni(q: Dict[str, str]) -> str:
    return normalize_host(q.get("sni") or q.get("servername") or q.get("serverName") or "")


def source_bonus(source: str) -> float:
    return float(SOURCE_BONUS.get(source, 0.0))


def sid_group(sid: str) -> str:
    sid = (sid or "").strip().lower()
    if not sid:
        return "empty"
    n = len(sid)
    if n <= 8:
        return "short"
    if n <= 16:
        return "medium"
    if n <= 32:
        return "long"
    return "xlong"


def make_family_key(host: str, port: int, q: Dict[str, str]) -> str:
    sni = choose_sni(q)
    fp = (q.get("fp", "") or "").strip().lower()
    flow = (q.get("flow", "") or "").strip().lower()
    sidg = sid_group(q.get("sid", ""))
    return f"{host}|{port}|{sni}|{fp}|{flow}|{sidg}"


def hostname_quality_score(host: str) -> float:
    host_l = normalize_host(host)

    if not host_l:
        return -10.0

    if is_ip_literal(host_l):
        return -8.0

    score = 0.0

    if "." in host_l:
        score += 4.0

    labels = host_l.split(".")
    tld = labels[-1] if labels else ""

    if len(labels) >= 2:
        score += 2.0

    if len(host_l) <= 64:
        score += 1.5
    elif len(host_l) > 120:
        score -= 3.0

    if tld in {"com", "net", "org", "io", "co", "de", "nl", "fr", "uk", "ru", "us"}:
        score += 1.5

    if any(x in host_l for x in ["localhost", "test", "example", "invalid"]):
        score -= 6.0

    digit_count = sum(1 for ch in host_l if ch.isdigit())
    if digit_count >= 8:
        score -= 2.0

    if "--" in host_l:
        score -= 1.0

    return score


def sni_quality_score(sni: str, host: str) -> float:
    if not sni:
        return -12.0

    score = hostname_quality_score(sni)

    if is_ip_literal(sni):
        score -= 8.0
    else:
        score += 4.0

    if sni == host:
        score += 5.0
    elif host.endswith("." + sni) or sni.endswith("." + host):
        score += 2.0

    return score


def compute_offline_score(source: str, host: str, port: int, q: Dict[str, str], tag: str) -> float:
    score = 0.0

    if port == 443:
        score += 22.0
    elif port == 8443:
        score += 15.0
    elif port in {2053, 2083}:
        score += 12.0

    sni = choose_sni(q)

    score += hostname_quality_score(host)
    score += sni_quality_score(sni, host)

    pbk = q.get("pbk", "").strip()
    if pbk and len(pbk) >= 20:
        score += 9.0
    if pbk and len(pbk) >= 40:
        score += 2.0

    sid = q.get("sid", "").strip()
    if sid and 0 < len(sid) <= 32:
        score += 5.0
    elif sid and len(sid) <= 64:
        score += 2.0

    spx = q.get("spx", "").strip()
    if spx:
        score += 2.0

    if q.get("fp", "").lower() == REQUIRED_FP:
        score += 7.0

    flow = q.get("flow", "").strip().lower()
    if flow == "xtls-rprx-vision":
        score += 4.0

    alpn = q.get("alpn", "").strip().lower()
    if alpn:
        if "h2" in alpn:
            score += 1.5
        if "http/1.1" in alpn:
            score += 1.0

    if tag and tag != "NO_TAG":
        score += 1.0

    score += source_bonus(source)

    return score


def make_dedupe_key(uuid: str, host: str, port: int, q: Dict[str, str]) -> str:
    sni = choose_sni(q)
    pbk = q.get("pbk", "").strip()
    sid = q.get("sid", "").strip()
    fp = q.get("fp", "").strip().lower()
    flow = q.get("flow", "").strip().lower()
    return f"{uuid}|{host}|{port}|{sni}|{pbk}|{sid}|{fp}|{flow}"


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

    if "encryption" not in q:
        q["encryption"] = "none"

    if "sni" not in q:
        sn = choose_sni(q)
        if sn:
            q["sni"] = sn

    final_pairs = []
    used = set()

    for k in ordered_keys:
        if k in q and q[k] != "":
            final_pairs.append((k, q[k]))
            used.add(k)

    for k in sorted(q.keys()):
        if k not in used and q[k] != "":
            final_pairs.append((k, q[k]))

    query_str = "&".join(
        f"{quote(str(k), safe='')}={quote(str(v), safe='')}"
        for k, v in final_pairs
    )

    return f"vless://{c.uuid}@{c.host}:{c.port}?{query_str}#{quote(c.tag, safe='')}"


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
        x = x.strip().strip("'\"")
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

    if sid and not looks_like_hex(sid, min_len=1):
        tel.rejects["sid_not_hex"] += 1
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
    family_key = make_family_key(host, port, q)

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
        family_key=family_key,
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
        "version": VERSION,
        "mode": "tcp_tls",
        "concurrency": LIVE_TEST_CONCURRENCY,
        "timeout_ms": LIVE_TEST_TIMEOUT_MS,
        "attempts": LIVE_TEST_ATTEMPTS,
        "tcp_attempts": LIVE_TEST_TCP_ATTEMPTS,
        "tls_attempts": LIVE_TEST_TLS_ATTEMPTS,
        "attempt_pause_ms": LIVE_TEST_ATTEMPT_PAUSE_MS,
        "targets": [
            {
                "id": c.dedupe_key,
                "host": c.host,
                "port": c.port,
                "sni": choose_sni(c.query),
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
            tel.live_probe_failed_reason = (
                f"prober_exit_{proc.returncode}: "
                f"{proc.stderr.decode('utf-8', errors='ignore')[:500]}"
            )
            return {}

        out = proc.stdout.decode("utf-8", errors="ignore").strip()
        data = json.loads(out)

        tel.live_probe_succeeded = True

        results = {}
        tls_seen = False

        for item in data.get("results", []):
            rid = str(item.get("id", "")).strip()
            if not rid:
                continue

            if "tls_ok" in item or "tls_latency_ms" in item or "tls_error" in item:
                tls_seen = True

            results[rid] = item

        tel.live_probe_tls_supported = tls_seen
        return results

    except subprocess.TimeoutExpired:
        tel.live_probe_succeeded = False
        tel.live_probe_failed_reason = "prober_timeout"
        return {}

    except Exception as e:
        tel.live_probe_succeeded = False
        tel.live_probe_failed_reason = f"prober_exception: {e}"
        return {}


def latency_score(latency_ms: Optional[float], kind: str = "tcp") -> float:
    if latency_ms is None:
        return 0.0

    x = float(latency_ms)

    if kind == "tls":
        if x <= 160:
            return 38.0
        if x <= 240:
            return 31.0
        if x <= 350:
            return 24.0
        if x <= 500:
            return 16.0
        if x <= 800:
            return 8.0
        if x <= 1300:
            return 2.0
        return -10.0

    if x <= 120:
        return 30.0
    if x <= 180:
        return 25.0
    if x <= 250:
        return 19.0
    if x <= 400:
        return 12.0
    if x <= 700:
        return 6.0
    if x <= 1200:
        return 1.0
    return -8.0


def ratio_score(successes: int, attempts: int, kind: str = "tcp") -> float:
    if attempts <= 0:
        return 0.0
    r = successes / attempts

    if kind == "tls":
        if r >= 1.0:
            return 45.0
        if r >= 0.75:
            return 28.0
        if r >= 0.5:
            return 12.0
        return -20.0

    if r >= 1.0:
        return 28.0
    if r >= 0.75:
        return 18.0
    if r >= 0.5:
        return 8.0
    return -12.0


def compute_live_score(
    tcp_ok: bool,
    tcp_latency_ms: Optional[float],
    tls_ok: bool,
    tls_latency_ms: Optional[float],
    tls_supported: bool,
    tcp_attempts: int = 0,
    tcp_successes: int = 0,
    tls_attempts: int = 0,
    tls_successes: int = 0,
) -> float:
    if not tcp_ok and tcp_successes <= 0:
        return 0.0

    score = 30.0

    if tcp_ok:
        score += 18.0

    score += latency_score(tcp_latency_ms, "tcp")

    if tcp_attempts > 0:
        score += ratio_score(tcp_successes, tcp_attempts, "tcp")

    if tls_supported:
        if tls_ok or tls_successes > 0:
            score += 55.0
            score += latency_score(tls_latency_ms, "tls")
        else:
            score -= 28.0

        if tls_attempts > 0:
            score += ratio_score(tls_successes, tls_attempts, "tls")
    else:
        score += 25.0

    return max(5.0, score)


def safe_float(value) -> Optional[float]:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def parse_attempt_stats(item: dict) -> Tuple[int, int, int, int]:
    tcp_attempts = 0
    tcp_successes = 0
    tls_attempts = 0
    tls_successes = 0

    if isinstance(item.get("tcp_attempts"), int):
        tcp_attempts = max(0, int(item.get("tcp_attempts")))
    if isinstance(item.get("tcp_successes"), int):
        tcp_successes = max(0, int(item.get("tcp_successes")))

    if isinstance(item.get("tls_attempts"), int):
        tls_attempts = max(0, int(item.get("tls_attempts")))
    if isinstance(item.get("tls_successes"), int):
        tls_successes = max(0, int(item.get("tls_successes")))

    if tcp_attempts == 0:
        tcp_attempts = 1
        tcp_successes = 1 if bool(item.get("tcp_ok", False)) else 0

    if ("tls_ok" in item or "tls_latency_ms" in item or "tls_error" in item) and tls_attempts == 0:
        tls_attempts = 1
        tls_successes = 1 if bool(item.get("tls_ok", False)) else 0

    return tcp_attempts, tcp_successes, tls_attempts, tls_successes


def merge_live_probe_scores(candidates: List[Candidate], results: Dict[str, dict], tel: Telemetry) -> None:
    tcp_latencies = []
    tls_latencies = []

    for c in candidates:
        item = results.get(c.dedupe_key)

        if not item:
            c.tcp_ok = False
            c.tcp_latency_ms = None
            c.tls_ok = False
            c.tls_latency_ms = None
            c.live_error = "missing_result"
            c.tls_error = ""
            c.live_score = 0.0
            continue

        c.tcp_ok = bool(item.get("tcp_ok", False))
        c.tls_ok = bool(item.get("tls_ok", False))

        tcp_lat = item.get("tcp_latency_ms", item.get("latency_ms", None))
        c.tcp_latency_ms = safe_float(tcp_lat)
        c.tls_latency_ms = safe_float(item.get("tls_latency_ms", None))

        c.live_error = str(item.get("error", "") or "")
        c.tls_error = str(item.get("tls_error", "") or "")

        (
            c.tcp_attempts,
            c.tcp_successes,
            c.tls_attempts,
            c.tls_successes,
        ) = parse_attempt_stats(item)

        c.live_score = compute_live_score(
            c.tcp_ok,
            c.tcp_latency_ms,
            c.tls_ok,
            c.tls_latency_ms,
            tel.live_probe_tls_supported,
            c.tcp_attempts,
            c.tcp_successes,
            c.tls_attempts,
            c.tls_successes,
        )

        tel.live_total_tested += 1

        if c.tcp_ok:
            tel.live_tcp_success += 1
            if c.tcp_latency_ms is not None:
                tcp_latencies.append(c.tcp_latency_ms)
        else:
            tel.live_tcp_fail += 1

        if tel.live_probe_tls_supported:
            if c.tls_ok:
                tel.live_tls_success += 1
                if c.tls_latency_ms is not None:
                    tls_latencies.append(c.tls_latency_ms)
            else:
                tel.live_tls_fail += 1

    apply_latency_telemetry(tel, tcp_latencies, prefix="tcp")
    apply_latency_telemetry(tel, tls_latencies, prefix="tls")


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


def apply_latency_telemetry(tel: Telemetry, latencies: List[float], prefix: str) -> None:
    if not latencies:
        return

    vals = sorted(latencies)

    mn = round(vals[0], 2)
    avg = round(sum(vals) / len(vals), 2)
    p50 = round(percentile(vals, 50), 2)
    p90 = round(percentile(vals, 90), 2)
    mx = round(vals[-1], 2)

    if prefix == "tcp":
        tel.live_tcp_latency_min_ms = mn
        tel.live_tcp_latency_avg_ms = avg
        tel.live_tcp_latency_p50_ms = p50
        tel.live_tcp_latency_p90_ms = p90
        tel.live_tcp_latency_max_ms = mx
    elif prefix == "tls":
        tel.live_tls_latency_min_ms = mn
        tel.live_tls_latency_avg_ms = avg
        tel.live_tls_latency_p50_ms = p50
        tel.live_tls_latency_p90_ms = p90
        tel.live_tls_latency_max_ms = mx


def assign_total_scores(candidates: List[Candidate], live_worked: bool, tls_supported: bool) -> None:
    for c in candidates:
        if live_worked:
            if tls_supported:
                c.total_score = (c.live_score * 1.0) + (c.offline_score * 0.18)
            else:
                c.total_score = (c.live_score * 1.0) + (c.offline_score * 0.22)
        else:
            c.total_score = c.offline_score


def similarity_penalty(
    c: Candidate,
    per_host: Dict[str, int],
    per_sni: Dict[str, int],
    per_fp: Dict[str, int],
    per_port: Dict[int, int],
    per_family: Dict[str, int],
) -> float:
    sni = choose_sni(c.query)
    fp = (c.query.get("fp", "") or "").strip().lower()

    penalty = 0.0
    penalty += per_host[c.host] * 8.0
    penalty += per_sni[sni] * 5.0
    penalty += per_fp[fp] * 2.0
    penalty += per_port[c.port] * 0.75
    penalty += per_family[c.family_key] * 14.0

    return penalty


def final_sort_key(c: Candidate, tls_supported: bool):
    tls_rank = 1 if c.tls_ok else 0
    tcp_rank = 1 if c.tcp_ok else 0

    tcp_lat = c.tcp_latency_ms if c.tcp_latency_ms is not None else 999999.0
    tls_lat = c.tls_latency_ms if c.tls_latency_ms is not None else 999999.0

    if tls_supported:
        return (
            c.selection_score,
            tls_rank,
            tcp_rank,
            -tls_lat,
            -tcp_lat,
            c.live_score,
            c.offline_score,
            1 if c.port == 443 else 0,
        )

    return (
        c.selection_score,
        tcp_rank,
        -tcp_lat,
        c.live_score,
        c.offline_score,
        1 if c.port == 443 else 0,
    )


def enrich_selection_scores(candidates: List[Candidate], tls_supported: bool) -> List[Candidate]:
    ranked = []

    seed_order = sorted(
        candidates,
        key=lambda c: (
            c.total_score,
            1 if c.tls_ok else 0,
            1 if c.tcp_ok else 0,
            c.offline_score,
        ),
        reverse=True,
    )

    per_host = defaultdict(int)
    per_sni = defaultdict(int)
    per_fp = defaultdict(int)
    per_port = defaultdict(int)
    per_family = defaultdict(int)

    for c in seed_order:
        sni = choose_sni(c.query)
        fp = (c.query.get("fp", "") or "").strip().lower()

        penalty = similarity_penalty(c, per_host, per_sni, per_fp, per_port, per_family)
        bonus = 0.0

        if per_host[c.host] == 0:
            bonus += 8.0
        if per_sni[sni] == 0:
            bonus += 6.0
        if per_family[c.family_key] == 0:
            bonus += 12.0
        if c.port == 443:
            bonus += 1.0

        c.selection_score = c.total_score + bonus - penalty
        ranked.append(c)

        per_host[c.host] += 1
        per_sni[sni] += 1
        per_fp[fp] += 1
        per_port[c.port] += 1
        per_family[c.family_key] += 1

    ranked.sort(key=lambda x: final_sort_key(x, tls_supported), reverse=True)
    return ranked


def final_select(candidates: List[Candidate], tls_supported: bool, live_worked: bool) -> List[Candidate]:
    ordered = enrich_selection_scores(candidates, tls_supported=tls_supported)

    chosen: List[Candidate] = []

    per_host = defaultdict(int)
    per_sni = defaultdict(int)
    per_fp = defaultdict(int)
    per_port = defaultdict(int)
    per_family = defaultdict(int)

    any_tcp_ok = live_worked and any(x.tcp_ok for x in ordered)
    any_tls_ok = live_worked and tls_supported and any(x.tls_ok for x in ordered)

    def can_take(c: Candidate) -> bool:
        sni = choose_sni(c.query)
        fp = (c.query.get("fp", "") or "").strip().lower()

        if per_host[c.host] >= MAX_PER_HOST:
            return False
        if per_sni[sni] >= MAX_PER_SNI:
            return False
        if per_fp[fp] >= MAX_PER_FP:
            return False
        if per_port[c.port] >= MAX_PER_PORT:
            return False
        if per_family[c.family_key] >= MAX_PER_FAMILY:
            return False
        return True

    def add_candidate(c: Candidate) -> None:
        sni = choose_sni(c.query)
        fp = (c.query.get("fp", "") or "").strip().lower()

        chosen.append(c)
        per_host[c.host] += 1
        per_sni[sni] += 1
        per_fp[fp] += 1
        per_port[c.port] += 1
        per_family[c.family_key] += 1

    # Pass 1: strongest live winners with unique-ish families
    for c in ordered:
        if len(chosen) >= MAX_OUTPUT:
            break
        if any_tls_ok and not c.tls_ok:
            continue
        if any_tcp_ok and not c.tcp_ok:
            continue
        if not can_take(c):
            continue
        add_candidate(c)

    # Pass 2: tcp-okay diverse fill
    if len(chosen) < MAX_OUTPUT:
        for c in ordered:
            if len(chosen) >= MAX_OUTPUT:
                break
            if c in chosen:
                continue
            if any_tcp_ok and not c.tcp_ok:
                continue
            if not can_take(c):
                continue
            add_candidate(c)

    # Pass 3: best remaining regardless of live class if probe was weak/unavailable
    if len(chosen) < MAX_OUTPUT:
        for c in ordered:
            if len(chosen) >= MAX_OUTPUT:
                break
            if c in chosen:
                continue
            if not can_take(c):
                continue
            add_candidate(c)

    return chosen


def compute_selection_telemetry(selected: List[Candidate], tel: Telemetry) -> None:
    if not selected:
        tel.selected_unique_hosts = 0
        tel.selected_unique_sni = 0
        tel.selected_unique_fp = 0
        tel.selected_unique_ports = 0
        tel.selected_unique_families = 0
        tel.selected_top_family_share = 0.0
        return

    sni_set = set()
    fp_set = set()
    host_set = set()
    port_set = set()
    family_set = set()
    family_counter = Counter()

    for c in selected:
        host_set.add(c.host)
        port_set.add(c.port)
        family_set.add(c.family_key)
        family_counter[c.family_key] += 1

        sni = choose_sni(c.query)
        if sni:
            sni_set.add(sni)

        fp = (c.query.get("fp", "") or "").strip().lower()
        if fp:
            fp_set.add(fp)

    tel.selected_unique_hosts = len(host_set)
    tel.selected_unique_sni = len(sni_set)
    tel.selected_unique_fp = len(fp_set)
    tel.selected_unique_ports = len(port_set)
    tel.selected_unique_families = len(family_set)

    top_family_count = family_counter.most_common(1)[0][1] if family_counter else 0
    tel.selected_top_family_share = round(top_family_count / len(selected), 4)


def make_final_tag(c: Candidate, rank: int) -> str:
    if rank <= TOP_NAME_COUNT:
        base = NAME_TOP
    elif rank <= MIDDLE_NAME_UNTIL:
        base = NAME_MIDDLE
    else:
        base = NAME_REST

    return f"{base} {rank:03d}"


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
        "source_count": len(ALL_SOURCES),
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
            "tls_supported": tel.live_probe_tls_supported,
            "total_tested": tel.live_total_tested,
            "tcp": {
                "success": tel.live_tcp_success,
                "fail": tel.live_tcp_fail,
                "latency": {
                    "min_ms": tel.live_tcp_latency_min_ms,
                    "avg_ms": tel.live_tcp_latency_avg_ms,
                    "p50_ms": tel.live_tcp_latency_p50_ms,
                    "p90_ms": tel.live_tcp_latency_p90_ms,
                    "max_ms": tel.live_tcp_latency_max_ms,
                },
            },
            "tls": {
                "success": tel.live_tls_success,
                "fail": tel.live_tls_fail,
                "latency": {
                    "min_ms": tel.live_tls_latency_min_ms,
                    "avg_ms": tel.live_tls_latency_avg_ms,
                    "p50_ms": tel.live_tls_latency_p50_ms,
                    "p90_ms": tel.live_tls_latency_p90_ms,
                    "max_ms": tel.live_tls_latency_max_ms,
                },
            },
        },
        "selection": {
            "max_output": MAX_OUTPUT,
            "caps": {
                "per_host": MAX_PER_HOST,
                "per_sni": MAX_PER_SNI,
                "per_fp": MAX_PER_FP,
                "per_port": MAX_PER_PORT,
                "per_family": MAX_PER_FAMILY,
            },
            "unique_hosts": tel.selected_unique_hosts,
            "unique_sni": tel.selected_unique_sni,
            "unique_fp": tel.selected_unique_fp,
            "unique_ports": tel.selected_unique_ports,
            "unique_families": tel.selected_unique_families,
            "top_family_share": tel.selected_top_family_share,
        },
        "naming": {
            "top_1_to": TOP_NAME_COUNT,
            "middle_6_to": MIDDLE_NAME_UNTIL,
            "top_name": NAME_TOP,
            "middle_name": NAME_MIDDLE,
            "rest_name": NAME_REST,
        },
        "final_selected": tel.final_selected,
    }

    with open(TELEMETRY_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def fallback_minimal_outputs_if_needed() -> None:
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
            f.write("")

    if not os.path.exists(TELEMETRY_FILE):
        with open(TELEMETRY_FILE, "w", encoding="utf-8", newline="\n") as f:
            json.dump(
                {
                    "version": VERSION,
                    "note": "fallback_created",
                },
                f,
                ensure_ascii=False,
                indent=2,
            )


def main() -> None:
    tel = Telemetry()

    try:
        all_links: List[Tuple[str, str]] = []
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

            for link in links:
                all_links.append((link, src))

        for raw_url, src in all_links:
            c = parse_candidate(raw_url, src, tel)
            if c is not None:
                parsed_candidates.append(c)

        tel.valid_candidates_before_dedupe = len(parsed_candidates)

        deduped = dedupe_candidates(parsed_candidates)
        tel.deduped_candidates = len(deduped)

        live_results = run_go_live_probe(deduped, tel)

        if tel.live_probe_succeeded:
            merge_live_probe_scores(deduped, live_results, tel)

        assign_total_scores(
            deduped,
            live_worked=tel.live_probe_succeeded,
            tls_supported=tel.live_probe_tls_supported,
        )

        selected = final_select(
            deduped,
            tls_supported=tel.live_probe_tls_supported,
            live_worked=tel.live_probe_succeeded,
        )

        tel.final_selected = len(selected)
        compute_selection_telemetry(selected, tel)

        write_output(selected)
        write_telemetry(tel)

        print(f"[{now_iso_like()}] Surgeon V{VERSION} done")
        print(f"Sources: {len(ALL_SOURCES)}")
        print(f"Extracted: {tel.total_extracted_links}")
        print(f"Valid before dedupe: {tel.valid_candidates_before_dedupe}")
        print(f"Deduped: {tel.deduped_candidates}")
        print(f"Live probe succeeded: {tel.live_probe_succeeded}")
        print(f"TLS supported by prober: {tel.live_probe_tls_supported}")
        print(f"TCP success: {tel.live_tcp_success}")
        print(f"TLS success: {tel.live_tls_success}")
        print(f"Selected unique hosts: {tel.selected_unique_hosts}")
        print(f"Selected unique SNI: {tel.selected_unique_sni}")
        print(f"Selected unique families: {tel.selected_unique_families}")
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
