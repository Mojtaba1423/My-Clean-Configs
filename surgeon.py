#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mojtaba Reality Surgeon V7.3

Implements (explicitly):
1) Multi-Layer Deduplication: host(or ip):port + sni + pbk
2) Golden Ports Priority: ONLY {443,2053,2083,8443} allowed
3) Mandatory Fingerprint: fp=chrome AND type=tcp for reality
4) Operator-Aware Ranking: heuristic scoring tuned for Iran networks
5) Failure Telemetry: detailed reject/accept counters written to JSON

Notes:
- No live tests (as requested).
- Base64-aware source body decoding (common for subscriptions).
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

VERSION = "7.3"

# ---- Sources (includes the 5 links you asked to add) ----
SOURCES = [
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/mix",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",

    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/mrvcoder/V2rayCollector/refs/heads/main/vless_iran.txt",
    "https://raw.githubusercontent.com/jafarm83/ConfigV2Ray/refs/heads/main/jafar_ultimate.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/refs/heads/main/main/vless.txt",
]

OUTPUT_FILE = "MOJTABA_CLEAN_LIST.txt"
TELEMETRY_FILE = "surgeon_telemetry.json"

MAX_OUTPUT = 128
MAX_PER_HOST = 2
FETCH_TIMEOUT = 20

# ---- Golden ports: strict allow-list ----
GOLDEN_PORTS = {443, 2053, 2083, 8443}

# ---- Mandatory fingerprint ----
MANDATORY_FP = "chrome"
MANDATORY_NET = "tcp"

# Reality required keys
REALITY_REQUIRED_KEYS = ("pbk", "sid", "sni")

# Operator-aware heuristics
PREFERRED_SNI_SUFFIXES = (".com", ".net", ".org", ".io", ".dev", ".app", ".co", ".me", ".ai")
SUSPICIOUS_SNI_TOKENS = (
    "telegram", "proxy", "vpn", "filter", "youtube", "porn", "adult",
    "fake", "test", "temp", "localhost", "local", "example", "invalid"
)

GOOD_FLOW = "xtls-rprx-vision"
# (در این نسخه strict هستیم: اگر flow هست و این نیست، رد)
ALLOWED_FLOWS = {GOOD_FLOW}

UA = "Mozilla/5.0 (X11; Linux x86_64) MojtabaRealitySurgeon/7.3"

# ---- Dark Luxury / Dark Sexy naming theme ----
TOP_5_LABEL = "🕯️🖤 Mojtaba1423"
BEST_NEXT_LABEL = "🌙🥀 @mojtaba_1423"
REST_LABEL = "🍷🦂 M_1423"


@dataclass
class Candidate:
    raw_url: str
    uuid: str
    host: str
    port: int
    query: Dict[str, str]
    tag: str
    score: int
    dedupe_key: str  # host(or ip):port + sni + pbk


def safe_b64decode(text: str) -> Optional[str]:
    s = (text or "").strip()
    if not s:
        return None

    compact = "".join(s.split())
    if not compact:
        return None

    # If already contains vless, don't b64 decode
    if "vless://" in compact.lower():
        return None

    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
    head = compact[:600]
    if any(ch not in allowed for ch in head):
        return None

    padding = (-len(compact)) % 4
    compact += "=" * padding

    for altchars in (None, b"-_"):
        try:
            raw = base64.b64decode(compact, altchars=altchars, validate=False)
            decoded = raw.decode("utf-8", errors="ignore")
            if "vless://" in decoded.lower():
                return decoded
        except Exception:
            pass
    return None


def maybe_decode_body(text: str) -> str:
    decoded = safe_b64decode(text)
    return decoded if decoded else (text or "")


def extract_vless_links(text: str) -> List[str]:
    matches = re.findall(r'vless://[^\s"<>\']+', text or "", flags=re.IGNORECASE)
    out, seen = [], set()
    for m in matches:
        x = m.strip().strip('\'"')
        x = x.rstrip("),.;]")
        if x.lower().startswith("vless://") and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def normalize_fp(fp: str) -> str:
    v = (fp or "").strip().lower()
    aliases = {
        "chromium": "chrome",
        "google chrome": "chrome",
    }
    return aliases.get(v, v)


def clean_host(host: str) -> str:
    return (host or "").strip().strip(".").lower()


def parse_query_single(query: str) -> Dict[str, str]:
    parsed = parse_qs(query or "", keep_blank_values=True)
    out = {}
    for k, v in parsed.items():
        if not v:
            continue
        out[k.lower()] = (v[0] or "").strip()
    return out


def is_ipv4(host: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host or ""))


def looks_like_domain(host: str) -> bool:
    h = clean_host(host)
    if not h or len(h) > 253:
        return False
    if "." not in h:
        return False
    if is_ipv4(h):
        return False
    labels = h.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False
    return True


def should_reject_sni(sni: str) -> bool:
    s = clean_host(sni)
    if not looks_like_domain(s):
        return True
    for tok in SUSPICIOUS_SNI_TOKENS:
        if tok in s:
            return True
    return False


def parse_vless_url(url: str) -> Optional[Tuple[str, str, int, Dict[str, str], str]]:
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "vless":
            return None
        uuid = unquote(parsed.username or "").strip()
        host = clean_host(parsed.hostname or "")
        port = int(parsed.port or 0)
        query = parse_query_single(parsed.query)
        tag = unquote(parsed.fragment or "").strip()
        if not uuid or not host or port <= 0:
            return None
        return uuid, host, port, query, tag
    except Exception:
        return None


def build_dedupe_key(host: str, port: int, sni: str, pbk: str) -> str:
    # Multi-layer dedupe per spec: IP(or host):Port + SNI + PBK
    # If host is an IP, it's already IP. Otherwise host is domain (we can't resolve IP offline here).
    return f"{clean_host(host)}:{port}|{clean_host(sni)}|{(pbk or '').strip()}"


def build_rank_label(rank: int) -> str:
    if rank <= 5:
        return TOP_5_LABEL
    elif rank <= 15:
        return BEST_NEXT_LABEL
    return REST_LABEL


def decorate_tag(rank: int, original_tag: str, score: int, port: int) -> str:
    label = build_rank_label(rank)
    base_tag = (original_tag or "").strip()

    return f"{label} | score:{score}"


def encode_vless(uuid: str, host: str, port: int, query: Dict[str, str], tag: str) -> str:
    query_items = []
    for k in sorted(query.keys()):
        query_items.append(f"{quote(str(k))}={quote(str(query[k]))}")
    query_str = "&".join(query_items)
    base = f"vless://{uuid}@{host}:{port}"
    if query_str:
        base += f"?{query_str}"
    if tag:
        base += f"#{quote(tag)}"
    return base


def score_operator_aware(host: str, port: int, sni: str, fp: str, flow: str, alpn: str, tag: str) -> int:
    """
    Heuristic scoring tuned for Iran:
    - Golden ports are mandatory already, still give differentiation
    - Good domain-like SNI, "enterprise-like" suffix, not suspicious
    - flow vision preferred
    - alpn h2 helpful
    - host != sni adds slight diversity advantage
    """
    score = 0

    # base: reality tcp validated
    score += 100

    # port weights (still differentiate among golden)
    if port == 443:
        score += 40
    elif port in (2053, 2083):
        score += 26
    elif port == 8443:
        score += 20

    # sni quality
    if sni.endswith(PREFERRED_SNI_SUFFIXES):
        score += 14
    # longer/more "real" looking domain gets slight bonus (bounded)
    score += min(max(len(sni) - 10, 0), 12)

    # host/sni mismatch slight plus (cdn-fronting-ish diversity)
    if clean_host(host) != clean_host(sni):
        score += 6

    # mandatory fp=chrome => reward it
    if fp == "chrome":
        score += 18

    if flow == GOOD_FLOW:
        score += 22

    a = (alpn or "").lower()
    if "h2" in a:
        score += 6
    if "http/1.1" in a:
        score += 2

    if tag:
        score += 1

    return score


def validate_and_build(raw_url: str, counters: Dict[str, int]) -> Optional[Candidate]:
    parsed = parse_vless_url(raw_url)
    if not parsed:
        counters["rejected_parse"] += 1
        return None

    uuid, host, port, query, tag = parsed

    security = (query.get("security", "") or "").strip().lower()
    net = (query.get("type", "") or "").strip().lower()
    pbk = (query.get("pbk", "") or "").strip()
    sid = (query.get("sid", "") or "").strip()
    sni = clean_host((query.get("sni", "") or "").strip())
    fp = normalize_fp((query.get("fp", "") or "").strip())
    flow = (query.get("flow", "") or "").strip().lower()
    alpn = (query.get("alpn", "") or "").strip()

    if security != "reality":
        counters["rejected_non_reality"] += 1
        return None

    if net != MANDATORY_NET:
        counters["rejected_non_tcp"] += 1
        return None

    # Golden ports strict
    if port not in GOLDEN_PORTS:
        counters["rejected_non_golden_port"] += 1
        return None

    # Mandatory fp=chrome strict
    if fp != MANDATORY_FP:
        # includes: missing fp OR different fp
        counters["rejected_fp_not_chrome"] += 1
        return None

    # Required keys
    for k in REALITY_REQUIRED_KEYS:
        if not (query.get(k, "") or "").strip():
            counters[f"rejected_missing_{k}"] += 1
            return None

    # Basic sanity
    if not uuid:
        counters["rejected_empty_uuid"] += 1
        return None

    # Host: allow domain OR ipv4 (some configs use IP host)
    if not (looks_like_domain(host) or is_ipv4(host)):
        counters["rejected_bad_host"] += 1
        return None

    # SNI must be good domain and not suspicious
    if should_reject_sni(sni):
        counters["rejected_bad_sni"] += 1
        return None

    # flow strict: if present must be vision; if missing -> reject (strict mode)
    # (اگر می‌خواهی flow اختیاری باشد، بگو تا تغییر بدهم)
    if not flow:
        counters["rejected_missing_flow"] += 1
        return None
    if flow not in ALLOWED_FLOWS:
        counters["rejected_bad_flow"] += 1
        return None

    # pbk/sid sanity
    if len(pbk) < 8:
        counters["rejected_short_pbk"] += 1
        return None
    if len(sid) < 1:
        counters["rejected_short_sid"] += 1
        return None

    score = score_operator_aware(host, port, sni, fp, flow, alpn, tag)
    dedupe_key = build_dedupe_key(host, port, sni, pbk)

    counters["validated_ok"] += 1
    return Candidate(
        raw_url=raw_url,
        uuid=uuid,
        host=host,
        port=port,
        query=query,
        tag=tag,
        score=score,
        dedupe_key=dedupe_key,
    )


def fetch_all() -> Tuple[str, List[dict]]:
    source_stats = []
    chunks: List[str] = []

    for url in SOURCES:
        stat = {"url": url, "ok": False, "status_code": 0, "bytes": 0, "error": ""}
        try:
            r = requests.get(url, timeout=FETCH_TIMEOUT, headers={"User-Agent": UA})
            stat["status_code"] = r.status_code
            if r.status_code != 200:
                stat["error"] = f"http_{r.status_code}"
                source_stats.append(stat)
                continue

            body = r.text or ""
            body = maybe_decode_body(body)
            stat["bytes"] = len(body.encode("utf-8", errors="ignore"))
            stat["ok"] = True
            chunks.append(body)
            source_stats.append(stat)
        except Exception as e:
            stat["error"] = str(e)[:300]
            source_stats.append(stat)

    return "\n".join(chunks), source_stats


def dedupe_best_by_key(candidates: List[Candidate], counters: Dict[str, int]) -> List[Candidate]:
    best: Dict[str, Candidate] = {}
    for c in candidates:
        prev = best.get(c.dedupe_key)
        if prev is None:
            best[c.dedupe_key] = c
        else:
            counters["dedupe_collisions"] += 1
            if c.score > prev.score:
                best[c.dedupe_key] = c
    return list(best.values())


def final_select(candidates: List[Candidate], counters: Dict[str, int]) -> List[Candidate]:
    ranked = sorted(
        candidates,
        key=lambda c: (-c.score, c.host, c.port, c.tag)
    )

    selected: List[Candidate] = []
    per_host: Dict[str, int] = {}

    for c in ranked:
        cnt = per_host.get(c.host, 0)
        if cnt >= MAX_PER_HOST:
            counters["rejected_host_cap"] += 1
            continue
        selected.append(c)
        per_host[c.host] = cnt + 1
        if len(selected) >= MAX_OUTPUT:
            break

    counters["selected_final"] = len(selected)
    return selected


def write_output(candidates: List[Candidate]) -> None:
    lines = []
    for idx, c in enumerate(candidates, start=1):
        final_tag = decorate_tag(
            rank=idx,
            original_tag=c.tag,
            score=c.score,
            port=c.port,
        )
        lines.append(encode_vless(c.uuid, c.host, c.port, c.query, final_tag))

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        if lines:
            f.write("\n".join(lines) + "\n")
        else:
            f.write("")


def write_telemetry(data: dict) -> None:
    with open(TELEMETRY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def process() -> dict:
    started = time.time()

    counters = {
        "rejected_parse": 0,
        "rejected_non_reality": 0,
        "rejected_non_tcp": 0,
        "rejected_non_golden_port": 0,
        "rejected_fp_not_chrome": 0,
        "rejected_missing_pbk": 0,
        "rejected_missing_sid": 0,
        "rejected_missing_sni": 0,
        "rejected_empty_uuid": 0,
        "rejected_bad_host": 0,
        "rejected_bad_sni": 0,
        "rejected_missing_flow": 0,
        "rejected_bad_flow": 0,
        "rejected_short_pbk": 0,
        "rejected_short_sid": 0,
        "validated_ok": 0,
        "dedupe_collisions": 0,
        "rejected_host_cap": 0,
        "selected_final": 0,
    }

    raw_text, source_stats = fetch_all()
    extracted_links = extract_vless_links(raw_text)

    validated: List[Candidate] = []
    for link in extracted_links:
        c = validate_and_build(link, counters)
        if c is not None:
            validated.append(c)

    deduped = dedupe_best_by_key(validated, counters)
    selected = final_select(deduped, counters)

    write_output(selected)

    summary = {
        "version": VERSION,
        "sources_total": len(SOURCES),
        "sources_ok": sum(1 for s in source_stats if s["ok"]),
        "source_stats": source_stats,

        "raw_text_size": len(raw_text.encode("utf-8", errors="ignore")),
        "extracted_links": len(extracted_links),

        "validated_candidates": len(validated),
        "deduped_candidates": len(deduped),
        "final_output": len(selected),

        "max_output": MAX_OUTPUT,
        "max_per_host": MAX_PER_HOST,

        "golden_ports": sorted(list(GOLDEN_PORTS)),
        "mandatory_fp": MANDATORY_FP,
        "mandatory_net": MANDATORY_NET,
        "live_test_enabled": False,

        "counters": counters,

        "output_file": OUTPUT_FILE,
        "telemetry_file": TELEMETRY_FILE,
        "elapsed_sec": round(time.time() - started, 3),
    }

    write_telemetry(summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


if __name__ == "__main__":
    process()
