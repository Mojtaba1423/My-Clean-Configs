#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import asyncio
import json
import re
import socket
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlparse

import requests


VERSION = "7.1"

SOURCES = [
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/mix",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
]

OUTPUT_FILE = "MOJTABA_CLEAN_LIST.txt"
TELEMETRY_FILE = "surgeon_telemetry.json"

MAX_OUTPUT = 96
MAX_PER_HOST = 2

PHASE2_CANDIDATES = 120
LIVE_TEST_ENABLED = True
LIVE_TEST_MODE = "tcp"   # "off" | "dns" | "tcp"
LIVE_TEST_WORKERS = 16

FETCH_TIMEOUT = 20
DNS_TIMEOUT = 1.0
TCP_TIMEOUT = 1.2
USER_AGENT = "Mozilla/5.0 (Mojtaba-Reality-Surgeon-V7.1)"

GOOD_PORTS = {443, 8443, 2053, 2083, 2087, 2096}
BAD_PORTS = {80, 81, 88, 8080, 8880, 2052, 2082, 2086, 2095}
GOOD_FLOWS = {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}
GOOD_FPS = {"chrome", "firefox", "safari", "edge", "ios", "android"}

SUSPICIOUS_SNI_TOKENS = {
    "cloudflare", "workers", "github", "localhost", "127.0.0.1",
    "example", "test", "invalid", "fake", "temp", "random",
}

PREFERRED_SNI_SUFFIXES = (".com", ".net", ".org", ".io", ".co", ".dev", ".app")


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
    key: str = ""
    notes: list[str] = field(default_factory=list)

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


def normalize_fp(fp: str) -> str:
    fp = (fp or "").strip().lower()
    if fp in {"chromium", "chrome"}:
        return "chrome"
    if fp in GOOD_FPS:
        return fp
    return "chrome"


def clean_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def parse_query_single(query: str) -> dict[str, str]:
    parsed = parse_qs(query, keep_blank_values=True)
    return {k: (v[-1] if v else "") for k, v in parsed.items()}


def looks_like_domain(name: str) -> bool:
    if not name or len(name) > 253 or " " in name:
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
        return True
    return "." in name and all(part and len(part) <= 63 for part in name.split("."))


def should_reject_sni(sni: str) -> bool:
    sni = clean_host(sni)
    if not sni or not looks_like_domain(sni):
        return True
    return any(token in sni for token in SUSPICIOUS_SNI_TOKENS)


def build_candidate_key(host: str, port: int, sni: str, pbk: str, sid: str) -> str:
    return f"{clean_host(host)}:{port}|{clean_host(sni)}|{pbk.strip()}|{sid.strip()}"


def encode_vless(c: Candidate) -> str:
    query = c.params.copy()
    query["fp"] = normalize_fp(query.get("fp", "chrome"))
    query_str = urlencode(query, doseq=False, quote_via=quote)
    fragment = quote(c.fragment or "", safe="")
    return f"vless://{c.uuid}@{c.host}:{c.port}?{query_str}#{fragment}"


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

    if p.get("security", "").lower() != "reality":
        return None

    net = p.get("type", "").strip().lower()
    if net and net != "tcp":
        return None

    # softer reality checks
    if not p.get("pbk", "").strip():
        return None
    if not p.get("sni", "").strip():
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
    if not (1 <= candidate.port <= 65535):
        return None

    score = 0.0

    if candidate.port == 443:
        score += 40
    elif candidate.port in GOOD_PORTS:
        score += 26
    else:
        score += 10

    flow = p.get("flow", "").strip().lower()
    if flow in GOOD_FLOWS:
        score += 16
    elif flow:
        score += 6
    else:
        score += 3

    if p["fp"] == "chrome":
        score += 12
    else:
        score += 8

    sni = p["sni"]
    if sni == candidate.host:
        score += 6
    if any(sni.endswith(suf) for suf in PREFERRED_SNI_SUFFIXES):
        score += 10

    if len(candidate.pbk) >= 20:
        score += 8
    else:
        score += 2

    if candidate.sid:
        score += 4

    candidate.base_score = score
    candidate.key = build_candidate_key(candidate.host, candidate.port, candidate.sni, candidate.pbk, candidate.sid)
    candidate.normalized_url = encode_vless(candidate)
    return candidate


def fetch_all() -> tuple[str, list[dict[str, Any]]]:
    chunks: list[str] = []
    headers = {"User-Agent": USER_AGENT}
    source_stats: list[dict[str, Any]] = []

    for src in SOURCES:
        item = {
            "url": src,
            "ok": False,
            "status_code": None,
            "bytes": 0,
            "error": "",
        }
        try:
            r = requests.get(src, timeout=FETCH_TIMEOUT, headers=headers)
            item["status_code"] = r.status_code
            if r.ok and r.text:
                item["ok"] = True
                item["bytes"] = len(r.text.encode("utf-8", errors="ignore"))
                chunks.append(r.text)
            else:
                item["error"] = f"http_{r.status_code}"
        except Exception as e:
            item["error"] = f"{type(e).__name__}: {e}"
        source_stats.append(item)

    return "\n".join(chunks), source_stats


def extract_vless_links(text: str) -> list[str]:
    if not text:
        return []
    return re.findall(r"vless://[^\s\"'<>]+", text, flags=re.IGNORECASE)


async def resolve_host(host: str) -> tuple[bool, float | None]:
    loop = asyncio.get_running_loop()
    t0 = time.perf_counter()
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=DNS_TIMEOUT)
        return True, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, None


async def tcp_probe(host: str, port: int) -> tuple[bool, float | None]:
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, None


async def light_live_test_one(candidate: Candidate, sem: asyncio.Semaphore) -> tuple[str, float]:
    async with sem:
        if LIVE_TEST_MODE == "off":
            return candidate.key, 0.0

        if LIVE_TEST_MODE == "dns":
            ok, ms = await resolve_host(candidate.host)
            if not ok:
                return candidate.key, -8.0
            if ms is not None and ms < 150:
                return candidate.key, 10.0
            return candidate.key, 6.0

        # tcp mode
        ok, ms = await tcp_probe(candidate.host, candidate.port)
        if not ok:
            return candidate.key, -10.0
        if ms is not None and ms < 250:
            return candidate.key, 16.0
        return candidate.key, 10.0


async def run_live_phase(candidates: list[Candidate]) -> dict[str, float]:
    if not candidates or LIVE_TEST_MODE == "off":
        return {}

    sem = asyncio.Semaphore(LIVE_TEST_WORKERS)
    tasks = [asyncio.create_task(light_live_test_one(c, sem)) for c in candidates]
    results: dict[str, float] = {}
    done = await asyncio.gather(*tasks, return_exceptions=True)

    for item in done:
        if isinstance(item, Exception):
            continue
        key, score = item
        results[key] = score

    return results


def phase1_build_candidates(text: str) -> tuple[list[Candidate], int]:
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
    return items, len(links)


def rerank_candidates(candidates: list[Candidate], live_scores: dict[str, float]) -> list[Candidate]:
    ranked: list[Candidate] = []

    for c in candidates:
        c.live_score = live_scores.get(c.key, 0.0)
        c.final_score = c.base_score + c.live_score
        ranked.append(c)

    ranked.sort(key=lambda x: (x.final_score, x.base_score), reverse=True)
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


def write_telemetry(data: dict[str, Any]) -> None:
    with open(TELEMETRY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def process() -> dict[str, Any]:
    t0 = time.perf_counter()

    raw_text, source_stats = fetch_all()
    phase1_candidates, extracted_links = phase1_build_candidates(raw_text)

    top_for_live = phase1_candidates[:PHASE2_CANDIDATES]

    live_scores: dict[str, float] = {}
    if LIVE_TEST_ENABLED and top_for_live:
        try:
            live_scores = asyncio.run(run_live_phase(top_for_live))
        except Exception:
            live_scores = {}

    reranked = rerank_candidates(phase1_candidates, live_scores)
    final_items = final_select(reranked)

    # fallback: never publish empty if validated candidates exist
    if not final_items and phase1_candidates:
        final_items = final_select(phase1_candidates)

    write_output(final_items)

    elapsed = round(time.perf_counter() - t0, 3)

    summary = {
        "version": VERSION,
        "sources_total": len(SOURCES),
        "sources_ok": sum(1 for s in source_stats if s["ok"]),
        "source_stats": source_stats,
        "raw_text_size": len(raw_text),
        "extracted_links": extracted_links,
        "validated_candidates": len(phase1_candidates),
        "phase2_candidates": len(top_for_live),
        "live_results": len(live_scores),
        "final_output": len(final_items),
        "live_test_enabled": LIVE_TEST_ENABLED,
        "live_test_mode": LIVE_TEST_MODE,
        "output_file": OUTPUT_FILE,
        "elapsed_sec": elapsed,
    }

    write_telemetry(summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


if __name__ == "__main__":
    process()
