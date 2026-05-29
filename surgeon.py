#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mojtaba Reality Surgeon V7.0
- Full rewrite with 4 phases
- Phase 1: fetch, parse, validate, dedupe, base-score
- Phase 2: lightweight live-test on top candidates
- Phase 3: re-rank based on live test results
- Phase 4: select final outputs with host cap

Target:
- Python 3.13+
- GitHub Actions friendly
- Fast and conservative
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import socket
import ssl
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, quote

import requests


# =========================
# CONFIG
# =========================

VERSION = "7.0"

SOURCES = [
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/mix",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
]

OUTPUT_FILE = "MOJTABA_CLEAN_LIST.txt"

MAX_OUTPUT = 96
MAX_PER_HOST = 2

PHASE2_CANDIDATES = 160   # if needed, reduce to 128
LIVE_TEST_ENABLED = True
LIVE_TEST_WORKERS = 8

FETCH_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (Mojtaba-Reality-Surgeon-V7)"

GLOBAL_LIVE_BUDGET = 4.0
DNS_TIMEOUT = 0.75
TCP_TIMEOUT = 1.00
TLS_TIMEOUT = 1.20
HTTP_TIMEOUT = 1.20

HTTP_PROBE_HOSTS = [
    "www.google.com",
    "www.youtube.com",
    "rr2---sn.googlevideo.com",
]

GOOD_PORTS = {
    443, 8443, 2053, 2083, 2087, 2096,
}

BAD_PORTS = {
    80, 81, 88, 8080, 8880, 2052, 2082, 2086, 2095,
}

GOOD_FLOWS = {
    "xtls-rprx-vision",
    "xtls-rprx-vision-udp443",
}

GOOD_FPS = {
    "chrome", "firefox", "safari", "edge", "ios", "android",
}

SUSPICIOUS_SNI_TOKENS = {
    "cloudflare",
    "workers",
    "github",
    "localhost",
    "127.0.0.1",
    "example",
    "test",
    "invalid",
    "fake",
    "temp",
    "random",
}

PREFERRED_SNI_SUFFIXES = (
    ".com",
    ".net",
    ".org",
    ".io",
    ".co",
    ".dev",
    ".app",
)

REALITY_REQUIRED_KEYS = ("pbk", "sid", "sni")


# =========================
# DATA MODEL
# =========================

@dataclass
class Candidate:
    raw_url: str
    scheme: str
    uuid: str
    host: str
    port: int
    params: dict[str, str]
    fragment: str = ""
    base_score: float = 0.0
    live_score: float = 0.0
    final_score: float = 0.0
    normalized_url: str = ""
    notes: list[str] = field(default_factory=list)
    key: str = ""

    def get(self, key: str, default: str = "") -> str:
        return self.params.get(key, default)

    @property
    def sni(self) -> str:
        return self.get("sni")

    @property
    def pbk(self) -> str:
        return self.get("pbk")

    @property
    def sid(self) -> str:
        return self.get("sid")

    @property
    def fp(self) -> str:
        return self.get("fp")

    @property
    def flow(self) -> str:
        return self.get("flow")

    @property
    def security(self) -> str:
        return self.get("security")

    @property
    def net(self) -> str:
        return self.get("type")

    @property
    def alpn(self) -> str:
        return self.get("alpn")

    @property
    def public_name(self) -> str:
        return self.fragment or f"{self.host}:{self.port}"


@dataclass
class LiveResult:
    dns_ok: bool = False
    tcp_ok: bool = False
    tls_ok: bool = False
    http_ok: bool = False

    dns_ms: float | None = None
    tcp_ms: float | None = None
    tls_ms: float | None = None
    http_ms: float | None = None

    error: str = ""


# =========================
# HELPERS
# =========================

def normalize_fp(fp: str) -> str:
    fp = (fp or "").strip().lower()
    if not fp:
        return "chrome"
    if fp in {"chromium", "chrome"}:
        return "chrome"
    if fp in GOOD_FPS:
        return fp
    return "chrome"


def clean_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def parse_query_single(query: str) -> dict[str, str]:
    parsed = parse_qs(query, keep_blank_values=True)
    return {k: (v[-1] if v else "") for k, v in parsed.items()}


def looks_like_domain(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    if " " in name:
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
        return True
    return "." in name and all(part and len(part) <= 63 for part in name.split("."))


def is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def should_reject_sni(sni: str) -> bool:
    sni = clean_host(sni)
    if not sni or not looks_like_domain(sni):
        return True
    return any(token in sni for token in SUSPICIOUS_SNI_TOKENS)


def build_candidate_key(host: str, port: int, sni: str, pbk: str, sid: str) -> str:
    return f"{clean_host(host)}:{port}|{clean_host(sni)}|{pbk.strip()}|{sid.strip()}"


def encode_vless(candidate: Candidate) -> str:
    query = candidate.params.copy()
    query["fp"] = normalize_fp(query.get("fp", "chrome"))
    query_str = urlencode(query, doseq=False, quote_via=quote)
    fragment = quote(candidate.fragment or "", safe="")
    return f"vless://{candidate.uuid}@{candidate.host}:{candidate.port}?{query_str}#{fragment}"


# =========================
# PARSE / VALIDATE / SCORE
# =========================

def parse_vless_url(url: str) -> Candidate | None:
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme.lower() != "vless":
            return None

        host = clean_host(parsed.hostname or "")
        port = parsed.port or 0
        uuid = parsed.username or ""
        params = parse_query_single(parsed.query)
        fragment = parsed.fragment or ""

        if not host or not port or not uuid:
            return None

        return Candidate(
            raw_url=url.strip(),
            scheme="vless",
            uuid=uuid.strip(),
            host=host,
            port=port,
            params=params,
            fragment=fragment.strip(),
        )
    except Exception:
        return None


def validate_and_score(candidate: Candidate) -> Candidate | None:
    p = candidate.params

    # Must be Reality
    if p.get("security", "").lower() != "reality":
        return None

    # If transport is present, only tcp
    net = p.get("type", "").strip().lower()
    if net and net != "tcp":
        return None

    # Required reality params
    for k in REALITY_REQUIRED_KEYS:
        if not p.get(k, "").strip():
            return None

    candidate.host = clean_host(candidate.host)
    p["sni"] = clean_host(p.get("sni", ""))
    p["fp"] = normalize_fp(p.get("fp", "chrome"))
    p["type"] = "tcp"
    p["security"] = "reality"

    if not looks_like_domain(candidate.host):
        return None

    if should_reject_sni(p["sni"]):
        return None

    if candidate.port in BAD_PORTS:
        return None

    score = 0.0

    # Port quality
    if candidate.port == 443:
        score += 38
    elif candidate.port in GOOD_PORTS:
        score += 24
    elif 1 <= candidate.port <= 65535:
        score += 8
    else:
        return None

    # Flow
    flow = p.get("flow", "").strip().lower()
    if flow in GOOD_FLOWS:
        score += 16
    elif flow:
        score += 5
    else:
        score += 2

    # Fingerprint
    if p["fp"] == "chrome":
        score += 12
    elif p["fp"] in GOOD_FPS:
        score += 8
    else:
        score += 3

    # SNI quality
    sni = p["sni"]
    if sni == candidate.host:
        score += 6

    if any(sni.endswith(suf) for suf in PREFERRED_SNI_SUFFIXES):
        score += 10

    if is_ip(candidate.host):
        score -= 10

    if len(candidate.pbk) >= 40:
        score += 8
    else:
        score += 2

    if 4 <= len(candidate.sid) <= 16:
        score += 6
    else:
        score += 1

    alpn = p.get("alpn", "").lower()
    if "h2" in alpn:
        score += 4
    if "http/1.1" in alpn:
        score += 2

    # Small penalties
    if any(tok in sni for tok in ("cdn", "cache", "edge-test")):
        score -= 2

    candidate.base_score = score
    candidate.key = build_candidate_key(
        candidate.host, candidate.port, candidate.sni, candidate.pbk, candidate.sid
    )
    candidate.normalized_url = encode_vless(candidate)
    return candidate


# =========================
# FETCH / EXTRACT
# =========================

def fetch_all() -> str:
    chunks: list[str] = []
    headers = {"User-Agent": USER_AGENT}

    for src in SOURCES:
        try:
            r = requests.get(src, timeout=FETCH_TIMEOUT, headers=headers)
            if r.ok and r.text:
                chunks.append(r.text)
        except Exception:
            continue

    return "\n".join(chunks)


def extract_vless_links(text: str) -> list[str]:
    if not text:
        return []
    return re.findall(r"vless://[^\s\"'<>]+", text, flags=re.IGNORECASE)


# =========================
# LIVE TEST
# =========================

async def resolve_host(host: str) -> tuple[bool, float | None, str]:
    loop = asyncio.get_running_loop()
    t0 = time.perf_counter()
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=DNS_TIMEOUT)
        ms = (time.perf_counter() - t0) * 1000
        return True, ms, ""
    except Exception as e:
        return False, None, f"dns:{type(e).__name__}"


async def tcp_probe(host: str, port: int) -> tuple[bool, float | None, str]:
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
        ms = (time.perf_counter() - t0) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, ms, ""
    except Exception as e:
        return False, None, f"tcp:{type(e).__name__}"


async def tls_probe(host: str, port: int, sni: str) -> tuple[bool, float | None, str]:
    t0 = time.perf_counter()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=port,
                ssl=ctx,
                server_hostname=sni or host,
            ),
            timeout=TLS_TIMEOUT,
        )
        ms = (time.perf_counter() - t0) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, ms, ""
    except Exception as e:
        return False, None, f"tls:{type(e).__name__}"


async def http_like_probe(host: str, port: int, sni: str) -> tuple[bool, float | None, str]:
    """
    Lightweight HTTP-over-TLS style probe.
    We only need a tiny response head, not a full download.
    """
    t0 = time.perf_counter()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    target_host = random.choice(HTTP_PROBE_HOSTS)
    req = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=port,
                ssl=ctx,
                server_hostname=sni or host,
            ),
            timeout=HTTP_TIMEOUT,
        )

        writer.write(req)
        await writer.drain()

        data = await asyncio.wait_for(reader.read(192), timeout=HTTP_TIMEOUT)
        ms = (time.perf_counter() - t0) * 1000

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        ok = bool(data)
        return ok, ms if ok else None, "" if ok else "http:empty"
    except Exception as e:
        return False, None, f"http:{type(e).__name__}"


async def live_test_one(candidate: Candidate, semaphore: asyncio.Semaphore, deadline: float) -> tuple[Candidate, LiveResult]:
    async with semaphore:
        result = LiveResult()

        if time.perf_counter() >= deadline:
            result.error = "budget_exceeded"
            return candidate, result

        dns_ok, dns_ms, dns_err = await resolve_host(candidate.host)
        result.dns_ok = dns_ok
        result.dns_ms = dns_ms
        if not dns_ok:
            result.error = dns_err
            return candidate, result

        if time.perf_counter() >= deadline:
            result.error = "budget_exceeded"
            return candidate, result

        tcp_ok, tcp_ms, tcp_err = await tcp_probe(candidate.host, candidate.port)
        result.tcp_ok = tcp_ok
        result.tcp_ms = tcp_ms
        if not tcp_ok:
            result.error = tcp_err
            return candidate, result

        if time.perf_counter() >= deadline:
            result.error = "budget_exceeded"
            return candidate, result

        tls_ok, tls_ms, tls_err = await tls_probe(candidate.host, candidate.port, candidate.sni)
        result.tls_ok = tls_ok
        result.tls_ms = tls_ms
        if not tls_ok:
            result.error = tls_err
            return candidate, result

        if time.perf_counter() >= deadline:
            result.error = "budget_exceeded"
            return candidate, result

        http_ok, http_ms, http_err = await http_like_probe(candidate.host, candidate.port, candidate.sni)
        result.http_ok = http_ok
        result.http_ms = http_ms
        if not http_ok:
            result.error = http_err

        return candidate, result


def score_live_result(candidate: Candidate, result: LiveResult) -> float:
    score = 0.0

    if result.dns_ok:
        score += 12
    if result.tcp_ok:
        score += 26
    if result.tls_ok:
        score += 34
    if result.http_ok:
        score += 22

    # latency bonuses / penalties
    for stage, ms in (
        ("dns", result.dns_ms),
        ("tcp", result.tcp_ms),
        ("tls", result.tls_ms),
        ("http", result.http_ms),
    ):
        if ms is None:
            continue
        if ms < 120:
            score += 6
        elif ms < 250:
            score += 4
        elif ms < 500:
            score += 2
        elif ms > 1200:
            score -= 3

    # strong penalties
    if result.dns_ok and not result.tcp_ok:
        score -= 10
    if result.tcp_ok and not result.tls_ok:
        score -= 16
    if result.tls_ok and not result.http_ok:
        score -= 4

    return score


async def run_live_phase(candidates: list[Candidate]) -> dict[str, LiveResult]:
    if not candidates:
        return {}

    semaphore = asyncio.Semaphore(LIVE_TEST_WORKERS)
    deadline = time.perf_counter() + GLOBAL_LIVE_BUDGET

    tasks = [
        asyncio.create_task(live_test_one(c, semaphore, deadline))
        for c in candidates
    ]

    results: dict[str, LiveResult] = {}
    done = await asyncio.gather(*tasks, return_exceptions=True)

    for item in done:
        if isinstance(item, Exception):
            continue
        candidate, live_result = item
        results[candidate.key] = live_result

    return results


# =========================
# PIPELINE
# =========================

def phase1_build_candidates(text: str) -> list[Candidate]:
    links = extract_vless_links(text)
    best_by_key: dict[str, Candidate] = {}

    for link in links:
        parsed = parse_vless_url(link)
        if not parsed:
            continue

        scored = validate_and_score(parsed)
        if not scored:
            continue

        current = best_by_key.get(scored.key)
        if current is None or scored.base_score > current.base_score:
            best_by_key[scored.key] = scored

    items = list(best_by_key.values())
    items.sort(key=lambda x: x.base_score, reverse=True)
    return items


def rerank_candidates(candidates: list[Candidate], live_results: dict[str, LiveResult]) -> list[Candidate]:
    ranked: list[Candidate] = []

    for c in candidates:
        live = live_results.get(c.key, LiveResult())
        c.live_score = score_live_result(c, live)

        # Heavier weight to real live success, but preserve base heuristic
        c.final_score = (c.base_score * 0.72) + (c.live_score * 1.28)

        # bonus for full pass
        if live.dns_ok and live.tcp_ok and live.tls_ok and live.http_ok:
            c.final_score += 12
        elif live.dns_ok and live.tcp_ok and live.tls_ok:
            c.final_score += 6

        ranked.append(c)

    ranked.sort(
        key=lambda x: (
            x.final_score,
            x.live_score,
            x.base_score,
            -x.port if x.port == 443 else 0,
        ),
        reverse=True,
    )
    return ranked


def final_select(candidates: list[Candidate]) -> list[Candidate]:
    selected: list[Candidate] = []
    per_host: defaultdict[str, int] = defaultdict(int)

    for c in candidates:
        if per_host[c.host] >= MAX_PER_HOST:
            continue
        selected.append(c)
        per_host[c.host] += 1
        if len(selected) >= MAX_OUTPUT:
            break

    return selected


def write_output(candidates: list[Candidate]) -> None:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for c in candidates:
            f.write(c.normalized_url + "\n")


def process() -> dict[str, Any]:
    t0 = time.perf_counter()

    raw_text = fetch_all()
    phase1_candidates = phase1_build_candidates(raw_text)

    top_for_live = phase1_candidates[:PHASE2_CANDIDATES]

    live_results: dict[str, LiveResult] = {}
    if LIVE_TEST_ENABLED and top_for_live:
        try:
            live_results = asyncio.run(run_live_phase(top_for_live))
        except Exception:
            live_results = {}

    reranked = rerank_candidates(phase1_candidates, live_results)
    final_items = final_select(reranked)
    write_output(final_items)

    elapsed = round(time.perf_counter() - t0, 3)

    summary = {
        "version": VERSION,
        "fetched_candidates": len(phase1_candidates),
        "phase2_candidates": len(top_for_live),
        "live_results": len(live_results),
        "final_output": len(final_items),
        "output_file": OUTPUT_FILE,
        "elapsed_sec": elapsed,
    }

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


if __name__ == "__main__":
    process()
