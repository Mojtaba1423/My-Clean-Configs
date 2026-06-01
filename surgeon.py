#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import dataclasses
from dataclasses import dataclass, field
import json
import os
import re
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlparse

try:
    import urllib.request
    import urllib.error
except Exception:
    urllib = None


VERSION = "2.0-rewrite"

OUTPUT_FILE = os.getenv("MOJTABA_CLEAN_LIST_FILENAME", "MOJTABA_CLEAN_LIST.txt")
LIVE_TEST_BINARY = os.getenv("LIVE_TEST_BINARY", "./prober")
LIVE_TEST_CONCURRENCY = int(os.getenv("LIVE_TEST_CONCURRENCY", "64"))
LIVE_TEST_TIMEOUT_MS = int(os.getenv("LIVE_TEST_TIMEOUT_MS", "3500"))
LIVE_TEST_PROCESS_TIMEOUT_SEC = int(os.getenv("LIVE_TEST_PROCESS_TIMEOUT_SEC", "120"))
LIVE_TEST_ATTEMPTS = int(os.getenv("LIVE_TEST_ATTEMPTS", "2"))
LIVE_TEST_TCP_ATTEMPTS = int(os.getenv("LIVE_TEST_TCP_ATTEMPTS", "2"))
LIVE_TEST_TLS_ATTEMPTS = int(os.getenv("LIVE_TEST_TLS_ATTEMPTS", "2"))
LIVE_TEST_ATTEMPT_PAUSE_MS = int(os.getenv("LIVE_TEST_ATTEMPT_PAUSE_MS", "150"))

MAX_OUTPUT = int(os.getenv("MAX_OUTPUT", "128"))
MAX_PER_HOST = int(os.getenv("MAX_PER_HOST", "4"))
MAX_PROBE_INPUT = int(os.getenv("MAX_PROBE_INPUT", "512"))

REQUEST_TIMEOUT_SEC = int(os.getenv("REQUEST_TIMEOUT_SEC", "20"))

DEFAULT_SOURCES = [
    # می‌توانی با env جایگزین کنی
]

LINK_RE = re.compile(
    r'(?i)\b(?:vless|vmess|trojan)://[^\s<>"\'`)\]]+'
)

BASE64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

GOLDEN_PORTS = {443, 2053, 2083, 2087, 2096, 8443, 80, 8080, 8880}
GOOD_TYPES = {"tcp", "ws", "grpc", "httpupgrade", "splithttp", "xhttp"}
GOOD_FPS = {"chrome", "firefox", "safari", "edge", "randomized", "random"}
GOOD_SECURITIES = {"reality", "tls", "xtls", ""}


@dataclass
class Candidate:
    raw_link: str
    scheme: str
    uuid: str
    host: str
    port: int
    tag: str = ""
    params: Dict[str, str] = field(default_factory=dict)

    sni: str = ""
    security: str = ""
    transport_type: str = ""
    fp: str = ""
    pbk: str = ""
    sid: str = ""
    flow: str = ""
    encryption: str = ""
    path: str = ""
    service_name: str = ""

    source: str = ""
    offline_score: float = 0.0
    live_score: float = 0.0
    final_score: float = 0.0

    tcp_ok: bool = False
    tls_ok: bool = False
    tcp_latency_ms: float = 0.0
    tls_latency_ms: float = 0.0
    error: str = ""

    def unique_key(self) -> Tuple[str, int, str, str, str, str]:
        return (
            self.host.lower(),
            self.port,
            self.uuid.lower(),
            self.security.lower(),
            self.transport_type.lower(),
            self.pbk.lower(),
        )


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def read_sources_from_env() -> List[str]:
    raw = os.getenv("SURGEON_SOURCES", "").strip()
    if not raw:
        return DEFAULT_SOURCES[:]
    parts = []
    for x in raw.splitlines():
        x = x.strip()
        if x:
            parts.append(x)
    return parts


def fetch_text(source: str) -> str:
    if source.startswith("http://") or source.startswith("https://"):
        req = urllib.request.Request(
            source,
            headers={
                "User-Agent": "Mozilla/5.0 surgeon.py rewrite",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC) as resp:
            data = resp.read()
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.decode("utf-8", errors="replace")
    else:
        with open(source, "r", encoding="utf-8", errors="replace") as f:
            return f.read()


def normalize_base64(s: str) -> str:
    s = s.strip()
    s = re.sub(r"\s+", "", s)
    s = s.replace("-", "+").replace("_", "/")
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    return s


def try_b64decode_text(s: str) -> Optional[str]:
    s = s.strip()
    if not s:
        return None
    compact = re.sub(r"\s+", "", s)
    if len(compact) < 16:
        return None
    if not BASE64_CHARS_RE.match(compact):
        return None
    try:
        decoded = base64.b64decode(normalize_base64(compact), validate=False)
    except Exception:
        return None
    if not decoded:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = decoded.decode("utf-8", errors="replace")
        except Exception:
            return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if not text or printable / max(1, len(text)) < 0.80:
        return None
    return text


def maybe_decode_base64_layers(text: str, max_depth: int = 2) -> List[str]:
    results = []
    seen = set()

    def rec(blob: str, depth: int) -> None:
        if depth > max_depth:
            return
        key = blob[:5000]
        if key in seen:
            return
        seen.add(key)

        results.append(blob)

        decoded_whole = try_b64decode_text(blob)
        if decoded_whole and decoded_whole != blob:
            rec(decoded_whole, depth + 1)

        for line in blob.splitlines():
            line = line.strip()
            if not line:
                continue
            decoded_line = try_b64decode_text(line)
            if decoded_line and decoded_line != line:
                rec(decoded_line, depth + 1)

    rec(text, 0)
    return results


def extract_proxy_links(text: str) -> List[str]:
    found = []
    seen = set()

    for blob in maybe_decode_base64_layers(text, max_depth=2):
        for m in LINK_RE.finditer(blob):
            link = m.group(0).strip().strip('\'"')
            if link not in seen:
                seen.add(link)
                found.append(link)

    return found


def safe_first(q: Dict[str, List[str]], key: str) -> str:
    val = q.get(key, [""])
    return val[0].strip() if val else ""


def pick_sni(q: Dict[str, List[str]], host: str) -> str:
    for key in ("sni", "serverName", "servername", "host"):
        v = safe_first(q, key)
        if v:
            return v.strip()
    return host


def looks_like_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if ":" in host and not HOST_RE.match(host.replace(":", "")):
        # احتمال ipv6؛ فعلاً ساده نگه می‌داریم
        return True
    return bool(HOST_RE.match(host))


def looks_like_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False


def sanitize_sid(sid: str) -> str:
    sid = sid.strip()
    if not sid:
        return ""
    if HEX_RE.match(sid):
        return sid.lower()
    cleaned = re.sub(r"[^0-9a-fA-F]", "", sid)
    return cleaned.lower()


def parse_vless_candidate(link: str, source: str = "") -> Optional[Candidate]:
    try:
        u = urlparse(link)
    except Exception:
        return None

    if u.scheme.lower() != "vless":
        return None

    host = (u.hostname or "").strip()
    port = u.port or 0
    uuid = unquote(u.username or "").strip()
    tag = unquote(u.fragment or "").strip()
    q = parse_qs(u.query, keep_blank_values=True)

    if not host or not uuid or not (1 <= port <= 65535):
        return None

    if not looks_like_hostname(host) and not looks_like_ip(host):
        return None

    params = {k: safe_first(q, k) for k in q.keys()}

    security = params.get("security", "").strip().lower()
    transport_type = params.get("type", "").strip().lower()
    fp = params.get("fp", "").strip().lower()
    pbk = params.get("pbk", "").strip()
    sid = sanitize_sid(params.get("sid", ""))
    flow = params.get("flow", "").strip().lower()
    encryption = params.get("encryption", "").strip().lower()
    path = params.get("path", "").strip()
    service_name = params.get("serviceName", params.get("service_name", "")).strip()
    sni = pick_sni(q, host).strip()

    c = Candidate(
        raw_link=link,
        scheme="vless",
        uuid=uuid,
        host=host,
        port=port,
        tag=tag,
        params=params,
        sni=sni,
        security=security,
        transport_type=transport_type,
        fp=fp,
        pbk=pbk,
        sid=sid,
        flow=flow,
        encryption=encryption,
        path=path,
        service_name=service_name,
        source=source,
    )
    return c


def parse_candidate(link: str, source: str = "") -> Optional[Candidate]:
    if not link:
        return None
    if link.lower().startswith("vless://"):
        return parse_vless_candidate(link, source=source)
    return None


def compute_offline_score(c: Candidate) -> float:
    score = 0.0

    if 1 <= c.port <= 65535:
        score += 5

    if c.port in GOLDEN_PORTS:
        score += 10

    if c.security == "reality":
        score += 35
    elif c.security in {"tls", "xtls"}:
        score += 18
    else:
        score += 3

    if c.transport_type == "tcp":
        score += 18
    elif c.transport_type in GOOD_TYPES:
        score += 10
    else:
        score += 2

    if c.fp in GOOD_FPS:
        score += 8
        if c.fp == "chrome":
            score += 4

    if c.pbk:
        score += 15
        if len(c.pbk) >= 20:
            score += 5

    if c.sni:
        score += 10
        if "." in c.sni:
            score += 3

    if c.sid:
        score += 4

    if c.flow in {"", "xtls-rprx-vision"}:
        score += 5

    if c.encryption in {"", "none"}:
        score += 5

    if c.path:
        score += 2

    if c.service_name:
        score += 2

    if looks_like_ip(c.host):
        score -= 3
    else:
        score += 4

    if c.tag:
        score += 1

    return score


def build_probe_target(c: Candidate) -> Dict:
    return {
        "id": f"{c.host}:{c.port}:{c.uuid[:8]}",
        "host": c.host,
        "port": c.port,
        "sni": c.sni or c.host,
    }


def run_go_live_probe(candidates: List[Candidate]) -> Dict[str, Dict]:
    if not candidates:
        return {}

    if not os.path.exists(LIVE_TEST_BINARY):
        log(f"[warn] prober not found: {LIVE_TEST_BINARY}")
        return {}

    payload = {
        "version": VERSION,
        "mode": "tls",
        "concurrency": LIVE_TEST_CONCURRENCY,
        "timeout_ms": LIVE_TEST_TIMEOUT_MS,
        "attempts": LIVE_TEST_ATTEMPTS,
        "tcp_attempts": LIVE_TEST_TCP_ATTEMPTS,
        "tls_attempts": LIVE_TEST_TLS_ATTEMPTS,
        "attempt_pause_ms": LIVE_TEST_ATTEMPT_PAUSE_MS,
        "targets": [build_probe_target(c) for c in candidates],
    }

    try:
        proc = subprocess.run(
            [LIVE_TEST_BINARY],
            input=json.dumps(payload).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=LIVE_TEST_PROCESS_TIMEOUT_SEC,
            check=False,
        )
    except Exception as e:
        log(f"[warn] prober execution failed: {e}")
        return {}

    if proc.returncode != 0:
        log(f"[warn] prober return code={proc.returncode}")
        if proc.stderr:
            log(proc.stderr.decode("utf-8", errors="replace"))
        return {}

    try:
        response = json.loads(proc.stdout.decode("utf-8", errors="replace"))
    except Exception as e:
        log(f"[warn] invalid prober json: {e}")
        return {}

    results = {}
    for item in response.get("results", []):
        rid = str(item.get("id", ""))
        if rid:
            results[rid] = item
    return results


def apply_live_results(candidates: List[Candidate], live_results: Dict[str, Dict]) -> None:
    for c in candidates:
        rid = f"{c.host}:{c.port}:{c.uuid[:8]}"
        item = live_results.get(rid)
        if not item:
            continue

        c.tcp_ok = bool(item.get("tcp_ok", False))
        c.tls_ok = bool(item.get("tls_ok", False))
        c.tcp_latency_ms = float(item.get("tcp_latency_ms", 0.0) or 0.0)
        c.tls_latency_ms = float(item.get("tls_latency_ms", 0.0) or 0.0)
        c.error = str(item.get("error", "") or "")

        live = 0.0
        if c.tcp_ok:
            live += 25
        if c.tls_ok:
            live += 35

        if c.tcp_latency_ms > 0:
            live += max(0.0, 20.0 - min(c.tcp_latency_ms, 4000.0) / 200.0)

        if c.tls_latency_ms > 0:
            live += max(0.0, 25.0 - min(c.tls_latency_ms, 4000.0) / 160.0)

        c.live_score = live
        c.final_score = c.offline_score + c.live_score


def dedupe_candidates(candidates: List[Candidate]) -> List[Candidate]:
    best = {}
    for c in candidates:
        key = c.unique_key()
        prev = best.get(key)
        if prev is None or c.offline_score > prev.offline_score:
            best[key] = c
    return list(best.values())


def rewrite_with_final_tag(c: Candidate, idx: int) -> str:
    q = dict(c.params)

    if c.security:
        q["security"] = c.security
    if c.transport_type:
        q["type"] = c.transport_type
    if c.sni:
        q["sni"] = c.sni
    if c.fp:
        q["fp"] = c.fp
    if c.pbk:
        q["pbk"] = c.pbk
    if c.sid:
        q["sid"] = c.sid
    if c.flow:
        q["flow"] = c.flow
    if c.encryption:
        q["encryption"] = c.encryption
    if c.path:
        q["path"] = c.path
    if c.service_name:
        q["serviceName"] = c.service_name

    query_parts = []
    for k in sorted(q.keys()):
        query_parts.append(f"{quote(str(k))}={quote(str(q[k]))}")

    query = "&".join(query_parts)
    tag = c.tag or f"MOJTABA-{idx}"
    return f"vless://{quote(c.uuid)}@{c.host}:{c.port}?{query}#{quote(tag)}"


def final_select(candidates: List[Candidate], max_output: int = MAX_OUTPUT) -> List[Candidate]:
    for c in candidates:
        if c.final_score <= 0:
            c.final_score = c.offline_score + c.live_score

    ordered = sorted(
        candidates,
        key=lambda x: (
            x.tls_ok,
            x.tcp_ok,
            x.final_score,
            x.offline_score,
            -x.tls_latency_ms if x.tls_latency_ms > 0 else 0,
            -x.tcp_latency_ms if x.tcp_latency_ms > 0 else 0,
        ),
        reverse=True,
    )

    selected = []
    host_count: Dict[str, int] = {}

    for c in ordered:
        h = c.host.lower()
        if host_count.get(h, 0) >= MAX_PER_HOST:
            continue
        selected.append(c)
        host_count[h] = host_count.get(h, 0) + 1
        if len(selected) >= max_output:
            break

    return selected


def write_output(selected: List[Candidate]) -> None:
    lines = [rewrite_with_final_tag(c, i + 1) for i, c in enumerate(selected)]
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines).strip() + ("\n" if lines else ""))


def collect_all_links(sources: List[str]) -> List[Tuple[str, str]]:
    collected = []

    for source in sources:
        try:
            text = fetch_text(source)
        except Exception as e:
            log(f"[warn] fetch failed for {source}: {e}")
            continue

        links = extract_proxy_links(text)
        vless_links = [x for x in links if x.lower().startswith("vless://")]

        log(f"[info] source={source} links={len(links)} vless={len(vless_links)}")

        for link in vless_links:
            collected.append((source, link))

    return collected


def main() -> int:
    t0 = time.time()

    sources = read_sources_from_env()
    if not sources:
        log("[warn] no sources configured in SURGEON_SOURCES and DEFAULT_SOURCES is empty")
        write_output([])
        return 0

    log(f"[info] surgeon version={VERSION}")
    log(f"[info] sources={len(sources)}")

    raw_links = collect_all_links(sources)
    log(f"[info] raw vless links={len(raw_links)}")

    parsed = []
    rejected = 0

    for source, link in raw_links:
        c = parse_candidate(link, source=source)
        if c is None:
            rejected += 1
            continue
        c.offline_score = compute_offline_score(c)
        c.final_score = c.offline_score
        parsed.append(c)

    log(f"[info] parsed={len(parsed)} rejected={rejected}")

    deduped = dedupe_candidates(parsed)
    log(f"[info] deduped={len(deduped)}")

    if not deduped:
        log("[warn] no valid candidates after parsing/dedup")
        write_output([])
        return 0

    preprobe = sorted(deduped, key=lambda x: x.offline_score, reverse=True)[:MAX_PROBE_INPUT]
    log(f"[info] preprobe={len(preprobe)}")

    live_results = run_go_live_probe(preprobe)
    log(f"[info] live_results={len(live_results)}")

    apply_live_results(preprobe, live_results)

    # merge updated probe scores back
    preprobe_map = {c.unique_key(): c for c in preprobe}
    merged = []
    for c in deduped:
        merged.append(preprobe_map.get(c.unique_key(), c))

    selected = final_select(merged, max_output=MAX_OUTPUT)
    log(f"[info] selected={len(selected)}")

    write_output(selected)

    dt = time.time() - t0
    log(f"[info] done in {dt:.2f}s output={OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
