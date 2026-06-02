#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MOJTABA Surgeon V7.8
- Strong extraction from mixed/base64-wrapped sources
- Strict VLESS parsing with normalization
- Offline scoring + capped live probing
- Per-host diversity limit
- Telemetry for debugging in GitHub Actions
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import random
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, unquote, urlsplit

import requests


OUTPUT_FILE = "m_configs.txt"
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
PROBE_CANDIDATE_LIMIT = int(os.getenv("PROBE_CANDIDATE_LIMIT", "900"))

LIVE_TEST_BINARY = os.getenv("LIVE_TEST_BINARY", "./prober")
LIVE_TEST_CONCURRENCY = int(os.getenv("LIVE_TEST_CONCURRENCY", "250"))
LIVE_TEST_TIMEOUT_MS = int(os.getenv("LIVE_TEST_TIMEOUT_MS", "2500"))
LIVE_TEST_PROCESS_TIMEOUT_SEC = int(os.getenv("LIVE_TEST_PROCESS_TIMEOUT_SEC", "480"))
LIVE_TEST_ATTEMPTS = int(os.getenv("LIVE_TEST_ATTEMPTS", "1"))
LIVE_TEST_TCP_ATTEMPTS = int(os.getenv("LIVE_TEST_TCP_ATTEMPTS", "1"))
LIVE_TEST_TLS_ATTEMPTS = int(os.getenv("LIVE_TEST_TLS_ATTEMPTS", "1"))
LIVE_TEST_ATTEMPT_PAUSE_MS = int(os.getenv("LIVE_TEST_ATTEMPT_PAUSE_MS", "50"))

TOP_NAME_COUNT = int(os.environ.get("TOP_NAME_COUNT", "5"))
MIDDLE_NAME_UNTIL = int(os.environ.get("MIDDLE_NAME_UNTIL", "32"))

NAME_TOP = "🕯️🖤 Mojtaba1423"
NAME_MIDDLE = "🌙⚫ @mojtaba_1423"
NAME_REST = "🦂🌑 M_1423"

ALLOWED_TRANSPORTS = {"tcp", "ws", "grpc", "httpupgrade", "splithttp"}
TLS_PORTS = {443, 8443, 2053, 2083, 2087, 2096}
DISCOURAGED_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
BAD_HOST_FRAGMENTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "example.com",
    "test",
    "yourdomain",
    "your-domain",
    "worker.dev",
}
BAD_REMARK_FRAGMENTS = {
    "telegram",
    "join",
    "subscribe",
    "free",
    "trial",
    "channel",
    "group",
}


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

    def key(self) -> Tuple[str, int, str, str, str, str, str, str]:
        return (
            self.host.lower(),
            self.port,
            (self.sni or "").lower(),
            (self.security or "").lower(),
            (self.type_ or "").lower(),
            (self.path or "/"),
            (self.service_name or ""),
            (self.pbk or ""),
        )

    def endpoint_key(self) -> Tuple[str, int]:
        return (self.host.lower(), self.port)

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
        for k in sorted(q.keys()):
            v = q.get(k)
            if v is None or v == "":
                continue
            parts.append(f"{k}={v}")

        query = "&".join(parts)
        fragment = quote(self.remark or "MOJTABA", safe="")

        if query:
            return f"vless://{self.uuid}@{self.host}:{self.port}?{query}#{fragment}"
        return f"vless://{self.uuid}@{self.host}:{self.port}#{fragment}"


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
            if not u:
                continue
            if len(u) < 32:
                continue
            if u not in seen:
                seen.add(u)
                results.append(u)

    return results


def normalize_host(host: str) -> str:
    host = host.strip().strip("[]").strip().lower().rstrip(".")
    return host


def is_ipv4(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.version == 4
    except ValueError:
        return False


def is_valid_domain(host: str) -> bool:
    if len(host) < 4 or len(host) > 253:
        return False
    if "." not in host:
        return False
    if host.startswith(".") or host.endswith("."):
        return False
    if ".." in host:
        return False
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return False

    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False

    tld = labels[-1]
    if len(tld) < 2:
        return False

    return True


def looks_like_uuid(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            value.strip(),
        )
    )


def is_bad_host(host: str) -> bool:
    h = host.lower()
    if any(x in h for x in BAD_HOST_FRAGMENTS):
        return True
    if h.startswith("192.168.") or h.startswith("10.") or h.startswith("172.16."):
        return True
    return False


def normalize_path(path: str) -> str:
    p = unquote((path or "/").strip() or "/")
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 256:
        p = p[:256]
    return p


def normalize_query_map(parts_query: str) -> Dict[str, str]:
    query_map_raw = parse_qs(parts_query, keep_blank_values=True)
    return {k: (v[-1].strip() if v else "") for k, v in query_map_raw.items()}


def parse_vless_candidate(uri: str) -> Optional[Candidate]:
    if not uri.lower().startswith("vless://"):
        return None

    try:
        parts = urlsplit(uri)
    except Exception:
        return None

    if not parts.netloc or "@" not in parts.netloc:
        return None

    try:
        userinfo, hostport = parts.netloc.rsplit("@", 1)
    except ValueError:
        return None

    uuid = userinfo.strip()
    if not looks_like_uuid(uuid):
        return None

    if ":" not in hostport:
        return None

    try:
        host, port_str = hostport.rsplit(":", 1)
    except ValueError:
        return None

    host = normalize_host(host)
    if not host or len(host) < 4 or is_bad_host(host):
        return None

    if not (is_ipv4(host) or is_valid_domain(host)):
        return None

    try:
        port = int(port_str)
    except ValueError:
        return None

    if port <= 0 or port > 65535:
        return None

    query = normalize_query_map(parts.query)

    security = (query.get("security") or "").strip().lower()
    transport = (query.get("type") or "tcp").strip().lower()
    path = normalize_path(query.get("path") or "/")
    sni = normalize_host((query.get("sni") or query.get("serverName") or "").strip())
    service_name = (query.get("serviceName") or "").strip()
    pbk = (query.get("pbk") or query.get("publicKey") or "").strip()
    sid = (query.get("sid") or query.get("shortId") or "").strip()
    fp = (query.get("fp") or query.get("fingerprint") or "").strip().lower()
    flow = (query.get("flow") or "").strip()
    alpn = (query.get("alpn") or "").strip()
    remark = unquote((parts.fragment or "").strip())

    if transport not in ALLOWED_TRANSPORTS:
        return None

    if security not in {"", "tls", "xtls", "reality"}:
        return None

    if security == "reality":
        if not pbk or len(pbk) < 8:
            return None
        if not sni:
            return None

    if security in {"tls", "xtls"} and not sni:
        return None

    if transport == "ws" and path == "/":
        return None

    if transport == "grpc" and not service_name:
        return None

    if port in DISCOURAGED_PORTS and security in {"", "tls", "xtls"}:
        return None

    if security in {"tls", "xtls", "reality"} and port not in TLS_PORTS and port < 1024:
        return None

    if sni and not (is_ipv4(sni) or is_valid_domain(sni)):
        return None

    c = Candidate(
        raw=uri.strip(),
        scheme="vless",
        uuid=uuid,
        host=host,
        port=port,
        path=path,
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

    score += 25

    if c.security == "reality":
        score += 45
    elif c.security in {"tls", "xtls"}:
        score += 22
    else:
        score -= 20

    if c.type_ == "grpc":
        score += 16
    elif c.type_ == "ws":
        score += 14
    elif c.type_ == "tcp":
        score += 10
    elif c.type_ in {"httpupgrade", "splithttp"}:
        score += 8

    if c.sni and c.sni != c.host:
        score += 8
    elif c.sni:
        score += 5

    if c.pbk:
        score += 12
    if c.sid:
        score += 6
    if c.fp:
        score += 4
    if c.flow:
        score += 2
    if c.alpn:
        score += 2

    if c.path and c.path != "/":
        score += 4

    if c.service_name:
        score += 5

    if c.port in TLS_PORTS:
        score += 12
    elif c.port in DISCOURAGED_PORTS:
        score -= 15
    elif 1 <= c.port <= 65535:
        score += 2

    if is_ipv4(c.host):
        score -= 4
    else:
        score += 6

    if c.host.endswith(".workers.dev") or c.host.endswith(".pages.dev"):
        score -= 12

    if c.remark:
        score += 1
        rr = c.remark.lower()
        if any(x in rr for x in BAD_REMARK_FRAGMENTS):
            score -= 2

    if len(c.host) >= 8:
        score += 2

    return score


def dedupe_candidates(cands: Iterable[Candidate]) -> List[Candidate]:
    best: Dict[Tuple[str, int, str, str, str, str, str, str], Candidate] = {}
    endpoint_counts: Dict[Tuple[str, int], int] = {}

    ordered = sorted(cands, key=lambda x: (x.offline_score, len(x.raw)), reverse=True)

    for c in ordered:
        k = c.key()
        prev = best.get(k)
        if prev is None or c.offline_score > prev.offline_score:
            best[k] = c

    deduped = list(best.values())

    final_list: List[Candidate] = []
    for c in sorted(deduped, key=lambda x: x.offline_score, reverse=True):
        ek = c.endpoint_key()
        cnt = endpoint_counts.get(ek, 0)
        if cnt >= 4:
            continue
        endpoint_counts[ek] = cnt + 1
        final_list.append(c)

    return final_list


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
        "version": "7.8",
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

        latency = item.get("latency_ms", item.get("tls_latency_ms", 999999))
        try:
            c.latency_ms = int(latency or 999999)
        except Exception:
            c.latency_ms = 999999

        err = str(item.get("error", "") or "").strip()
        tls_err = str(item.get("tls_error", "") or "").strip()
        c.error = err or tls_err

        live = 0
        if c.tcp_ok:
            live += 20
        if c.tls_ok:
            live += 55

        if c.latency_ms < 150:
            live += 22
        elif c.latency_ms < 350:
            live += 14
        elif c.latency_ms < 700:
            live += 7

        if c.tls_ok and c.security in {"tls", "xtls", "reality"}:
            live += 8

        c.live_score = live
        c.total_score = c.offline_score + c.live_score


def finalize_scores(cands: List[Candidate]) -> None:
    for c in cands:
        if c.total_score == 0:
            c.total_score = c.offline_score


def output_name_for_index(idx: int) -> str:
    if idx < TOP_NAME_COUNT:
        return NAME_TOP
    if idx < MIDDLE_NAME_UNTIL:
        return NAME_MIDDLE
    return NAME_REST


def apply_output_names(cands: List[Candidate]) -> None:
    for idx, c in enumerate(cands):
        c.remark = output_name_for_index(idx)


def select_best(cands: List[Candidate], max_output: int, max_per_host: int) -> List[Candidate]:
    ordered = sorted(
        cands,
        key=lambda x: (
            x.total_score,
            x.live_score,
            x.tls_ok,
            x.tcp_ok,
            x.offline_score,
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

    if selected:
        return selected

    return ordered[:max_output]


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
        "version": "7.8",
        "sources": [],
        "fetched_sources": 0,
        "extracted_uris": 0,
        "parsed_candidates": 0,
        "deduped_candidates": 0,
        "probe_limit": PROBE_CANDIDATE_LIMIT,
        "probe_input": 0,
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

    deduped_sorted = sorted(
        deduped,
        key=lambda x: (x.offline_score, len(x.host), len(x.path or "")),
        reverse=True,
    )

    probe_candidates = deduped_sorted[:PROBE_CANDIDATE_LIMIT]
    telemetry["probe_input"] = len(probe_candidates)
    log(f"[probe] probing {len(probe_candidates)} of {len(deduped_sorted)} candidates")

    live_results = run_live_probe(probe_candidates)
    telemetry["live_results"] = len(live_results)
    log(f"[probe] results={len(live_results)}")

    apply_live_results(probe_candidates, live_results)
    finalize_scores(deduped_sorted)

    selected = select_best(deduped_sorted, MAX_OUTPUT, MAX_PER_HOST)
    telemetry["selected"] = len(selected)
    log(f"[select] selected={len(selected)}")

    apply_output_names(selected)
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
