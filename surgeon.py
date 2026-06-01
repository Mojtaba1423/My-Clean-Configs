#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MOJTABA Surgeon V7.7
- Strong extraction from mixed/base64-wrapped sources
- Conservative VLESS parsing with normalization
- Offline scoring + optional live probing
- Per-host diversity limit
- Telemetry for debugging in GitHub Actions
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import random
import re
import socket
import string
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

import requests


OUTPUT_FILE = "MOJTABA_CLEAN_LIST.txt"
TELEMETRY_FILE = "surgeon_telemetry.json"

DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/mrvcoder/V2rayCollector/refs/heads/main/vless_iran.txt",
    "https://raw.githubusercontent.com/jafarm83/ConfigV2Ray/refs/heads/main/jafar_ultimate.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/refs/heads/main/main/vless.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/refs/heads/main/Configs/VLESS-DukeMehdi-Configs.txt",
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

USER_AGENTS = [
    "Mozilla/5.0",
    "curl/8.0",
    "Wget/1.21",
]

REQUEST_TIMEOUT = 20
MAX_OUTPUT = int(os.getenv("MAX_OUTPUT", "128"))
MAX_PER_HOST = int(os.getenv("MAX_PER_HOST", "2"))

LIVE_TEST_BINARY = os.getenv("LIVE_TEST_BINARY", "./prober")
LIVE_TEST_CONCURRENCY = int(os.getenv("LIVE_TEST_CONCURRENCY", "250"))
LIVE_TEST_TIMEOUT_MS = int(os.getenv("LIVE_TEST_TIMEOUT_MS", "4000"))
LIVE_TEST_PROCESS_TIMEOUT_SEC = int(os.getenv("LIVE_TEST_PROCESS_TIMEOUT_SEC", "240"))
LIVE_TEST_ATTEMPTS = int(os.getenv("LIVE_TEST_ATTEMPTS", "2"))
LIVE_TEST_TCP_ATTEMPTS = int(os.getenv("LIVE_TEST_TCP_ATTEMPTS", "2"))
LIVE_TEST_TLS_ATTEMPTS = int(os.getenv("LIVE_TEST_TLS_ATTEMPTS", "2"))
LIVE_TEST_ATTEMPT_PAUSE_MS = int(os.getenv("LIVE_TEST_ATTEMPT_PAUSE_MS", "150"))


@dataclass
class Candidate:
    raw: str
    scheme: str
    uuid: str
    host: str
    port: int
    path: str = "/"
    sni: str = ""
    security: str = ""
    transport: str = ""
    type_: str = ""
    service_name: str = ""
    pbk: str = ""
    sid: str = ""
    fp: str = ""
    flow: str = ""
    alpn: str = ""
    remark: str = ""
    query: Dict[str, str] = field(default_factory=dict)

    offline_score: int = 0
    live_score: int = 0
    total_score: int = 0

    tcp_ok: bool = False
    tls_ok: bool = False
    latency_ms: int = 999999
    error: str = ""

    def key(self) -> Tuple[str, int, str, str, str, str]:
        return (
            self.host.lower(),
            self.port,
            (self.sni or "").lower(),
            (self.path or "/"),
            (self.pbk or ""),
            (self.sid or ""),
        )

    def to_uri(self) -> str:
        q = dict(self.query)

        if self.type_:
            q["type"] = self.type_
        if self.security:
            q["security"] = self.security
        if self.sni:
            q["sni"] = self.sni
        if self.path:
            q["path"] = self.path
        if self.service_name:
            q["serviceName"] = self.service_name
        if self.pbk:
            q["pbk"] = self.pbk
        if self.sid:
            q["sid"] = self.sid
        if self.fp:
            q["fp"] = self.fp
        if self.flow:
            q["flow"] = self.flow
        if self.alpn:
            q["alpn"] = self.alpn

        parts = []
        for k, v in q.items():
            if v is None:
                continue
            parts.append(f"{k}={v}")
        query = "&".join(parts)
        fragment = self.remark or "MOJTABA"
        return f"vless://{self.uuid}@{self.host}:{self.port}?{query}#{fragment}"


def log(msg: str) -> None:
    print(msg, flush=True)


def load_sources() -> List[str]:
    env_sources = os.getenv("SOURCES", "").strip()
    if env_sources:
        return [x.strip() for x in env_sources.splitlines() if x.strip()]
    return DEFAULT_SOURCES[:]


def fetch_text(url: str) -> str:
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.text


def is_probably_base64(s: str) -> bool:
    t = "".join(s.strip().split())
    if len(t) < 24:
        return False
    if len(t) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", t))


def try_b64decode(s: str) -> Optional[str]:
    t = "".join(s.strip().split())
    try:
        data = base64.b64decode(t, validate=True)
        return data.decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return None


def maybe_decode_base64_layers(text: str, max_layers: int = 3) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []

    def visit(t: str, depth: int) -> None:
        if not t or t in seen:
            return
        seen.add(t)
        out.append(t)
        if depth >= max_layers:
            return

        candidates = [t]
        stripped = t.strip()
        if is_probably_base64(stripped):
            candidates.append(stripped)

        for c in candidates:
            decoded = try_b64decode(c)
            if decoded and decoded not in seen:
                visit(decoded, depth + 1)

    visit(text, 0)
    return out


def extract_candidate_uris(text: str) -> List[str]:
    results: List[str] = []
    seen: Set[str] = set()

    pattern = re.compile(r"(vless://[^\s'\"<>]+)", re.IGNORECASE)

    for layer in maybe_decode_base64_layers(text, max_layers=3):
        for m in pattern.findall(layer):
            u = m.strip()
            if u and u not in seen:
                seen.add(u)
                results.append(u)

    return results


def normalize_host(host: str) -> str:
    return host.strip().strip("[]").lower()


def parse_vless_candidate(uri: str) -> Optional[Candidate]:
    if not uri.lower().startswith("vless://"):
        return None

    try:
        parts = urlsplit(uri)
    except Exception:
        return None

    if not parts.netloc or "@" not in parts.netloc:
        return None

    userinfo, hostport = parts.netloc.rsplit("@", 1)
    uuid = userinfo.strip()
    if not uuid:
        return None

    if ":" not in hostport:
        return None

    host, port_str = hostport.rsplit(":", 1)
    host = normalize_host(host)
    if not host:
        return None

    try:
        port = int(port_str)
    except ValueError:
        return None

    if port <= 0 or port > 65535:
        return None

    query_map_raw = parse_qs(parts.query, keep_blank_values=True)
    query = {k: (v[-1] if v else "") for k, v in query_map_raw.items()}

    security = (query.get("security") or "").strip().lower()
    transport = (query.get("type") or "").strip().lower()
    path = unquote((query.get("path") or "/").strip() or "/")
    sni = (query.get("sni") or query.get("serverName") or "").strip().lower()
    service_name = (query.get("serviceName") or "").strip()
    pbk = (query.get("pbk") or query.get("publicKey") or "").strip()
    sid = (query.get("sid") or query.get("shortId") or "").strip()
    fp = (query.get("fp") or query.get("fingerprint") or "").strip()
    flow = (query.get("flow") or "").strip()
    alpn = (query.get("alpn") or "").strip()
    remark = unquote((parts.fragment or "").strip())

    c = Candidate(
        raw=uri.strip(),
        scheme="vless",
        uuid=uuid,
        host=host,
        port=port,
        path=path if path.startswith("/") else f"/{path}",
        sni=sni or host,
        security=security,
        transport=transport,
        type_=transport,
        service_name=service_name,
        pbk=pbk,
        sid=sid,
        fp=fp,
        flow=flow,
        alpn=alpn,
        remark=remark,
        query=query,
    )

    return c


def score_candidate(c: Candidate) -> int:
    score = 0

    if c.scheme == "vless":
        score += 20

    if c.security == "reality":
        score += 40
    elif c.security in ("tls", "xtls"):
        score += 15

    if c.type_ in ("tcp", "ws", "grpc"):
        score += 10

    if c.type_ == "tcp":
        score += 5

    if c.sni:
        score += 8

    if c.pbk:
        score += 12

    if c.sid:
        score += 6

    if c.fp:
        score += 4

    if c.path and c.path != "/":
        score += 3

    if c.service_name:
        score += 3

    if c.port in (443, 8443, 2053, 2083, 2087, 2096):
        score += 8
    elif 1 <= c.port <= 65535:
        score += 2

    host = c.host.lower()
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        score -= 2
    else:
        score += 4

    if len(host) >= 4:
        score += 2

    if c.remark:
        score += 1

    return score


def dedupe_candidates(cands: Iterable[Candidate]) -> List[Candidate]:
    best: Dict[Tuple[str, int, str, str, str, str], Candidate] = {}
    for c in cands:
        k = c.key()
        prev = best.get(k)
        if prev is None or c.offline_score > prev.offline_score:
            best[k] = c
    return list(best.values())


def build_probe_payload(cands: List[Candidate]) -> Dict:
    targets = []
    for idx, c in enumerate(cands):
        targets.append(
            {
                "id": str(idx),
                "host": c.host,
                "port": c.port,
                "sni": c.sni or c.host,
            }
        )

    return {
        "version": "7.7",
        "mode": "tls",
        "concurrency": LIVE_TEST_CONCURRENCY,
        "timeout_ms": LIVE_TEST_TIMEOUT_MS,
        "attempts": LIVE_TEST_ATTEMPTS,
        "tcp_attempts": LIVE_TEST_TCP_ATTEMPTS,
        "tls_attempts": LIVE_TEST_TLS_ATTEMPTS,
        "attempt_pause_ms": LIVE_TEST_ATTEMPT_PAUSE_MS,
        "targets": targets,
    }


def run_live_probe(cands: List[Candidate]) -> Dict[str, Dict]:
    if not cands:
        return {}

    if not os.path.isfile(LIVE_TEST_BINARY):
        log(f"[probe] binary not found: {LIVE_TEST_BINARY} -> offline only")
        return {}

    payload = build_probe_payload(cands)
    data = json.dumps(payload).encode("utf-8")

    try:
        proc = subprocess.run(
            [LIVE_TEST_BINARY],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=LIVE_TEST_PROCESS_TIMEOUT_SEC,
            check=False,
        )
    except Exception as e:
        log(f"[probe] process failed: {e}")
        return {}

    if proc.stderr:
        log(f"[probe][stderr] {proc.stderr.decode('utf-8', errors='ignore').strip()}")

    if not proc.stdout:
        log("[probe] empty stdout -> offline only")
        return {}

    try:
        obj = json.loads(proc.stdout.decode("utf-8", errors="ignore"))
    except Exception as e:
        log(f"[probe] invalid json: {e}")
        return {}

    results = {}
    for item in obj.get("results", []) or []:
        rid = str(item.get("id", "")).strip()
        if rid:
            results[rid] = item
    return results


def apply_live_results(cands: List[Candidate], result_map: Dict[str, Dict]) -> None:
    for idx, c in enumerate(cands):
        item = result_map.get(str(idx))
        if not item:
            c.live_score = 0
            c.total_score = c.offline_score
            continue

        c.tcp_ok = bool(item.get("tcp_ok", False))
        c.tls_ok = bool(item.get("tls_ok", False))
        c.latency_ms = int(item.get("latency_ms", 999999) or 999999)

        err = str(item.get("error", "") or "").strip()
        tls_err = str(item.get("tls_error", "") or "").strip()
        c.error = err or tls_err

        live = 0
        if c.tcp_ok:
            live += 20
        if c.tls_ok:
            live += 45

        if c.latency_ms < 150:
            live += 20
        elif c.latency_ms < 400:
            live += 12
        elif c.latency_ms < 900:
            live += 5

        c.live_score = live
        c.total_score = c.offline_score + c.live_score


def finalize_scores(cands: List[Candidate]) -> None:
    for c in cands:
        if c.total_score == 0:
            c.total_score = c.offline_score


def select_best(cands: List[Candidate], max_output: int, max_per_host: int) -> List[Candidate]:
    ordered = sorted(
        cands,
        key=lambda x: (
            x.total_score,
            x.live_score,
            x.offline_score,
            x.tls_ok,
            x.tcp_ok,
            -x.latency_ms,
        ),
        reverse=True,
    )

    selected: List[Candidate] = []
    host_counts: Dict[str, int] = {}

    for c in ordered:
        if len(selected) >= max_output:
            break
        cnt = host_counts.get(c.host, 0)
        if cnt >= max_per_host:
            continue
        selected.append(c)
        host_counts[c.host] = cnt + 1

    return selected


def write_output(cands: List[Candidate], path: str) -> None:
    lines = [c.to_uri() for c in cands]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).strip())
        if lines:
            f.write("\n")


def write_telemetry(data: Dict) -> None:
    with open(TELEMETRY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main() -> int:
    started = time.time()
    telemetry = {
        "version": "7.7",
        "sources": [],
        "fetched_sources": 0,
        "extracted_uris": 0,
        "parsed_candidates": 0,
        "deduped_candidates": 0,
        "live_results": 0,
        "selected": 0,
        "output_file": OUTPUT_FILE,
        "errors": [],
    }

    sources = load_sources()
    telemetry["sources"] = sources

    all_uris: List[str] = []

    log(f"[fetch] sources={len(sources)}")
    for url in sources:
        try:
            text = fetch_text(url)
            telemetry["fetched_sources"] += 1
            uris = extract_candidate_uris(text)
            all_uris.extend(uris)
            log(f"[extract] {url} -> {len(uris)} uri(s)")
        except Exception as e:
            msg = f"{url}: {e}"
            telemetry["errors"].append(msg)
            log(f"[error] {msg}")

    telemetry["extracted_uris"] = len(all_uris)

    parsed: List[Candidate] = []
    for uri in all_uris:
        c = parse_vless_candidate(uri)
        if not c:
            continue
        c.offline_score = score_candidate(c)
        c.total_score = c.offline_score
        parsed.append(c)

    telemetry["parsed_candidates"] = len(parsed)
    log(f"[parse] parsed={len(parsed)}")

    deduped = dedupe_candidates(parsed)
    telemetry["deduped_candidates"] = len(deduped)
    log(f"[dedupe] deduped={len(deduped)}")

    live_results = run_live_probe(deduped)
    telemetry["live_results"] = len(live_results)
    log(f"[probe] results={len(live_results)}")

    apply_live_results(deduped, live_results)
    finalize_scores(deduped)

    selected = select_best(deduped, MAX_OUTPUT, MAX_PER_HOST)
    telemetry["selected"] = len(selected)
    log(f"[select] selected={len(selected)}")

    write_output(selected, OUTPUT_FILE)

    telemetry["duration_sec"] = round(time.time() - started, 3)
    telemetry["output_nonempty"] = os.path.isfile(OUTPUT_FILE) and os.path.getsize(OUTPUT_FILE) > 0
    write_telemetry(telemetry)

    if not selected:
        log("[final] no candidate selected")
        return 1

    log(f"[final] wrote {len(selected)} configs to {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
