#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import contextlib
import csv
import datetime as dt
import hashlib
import json
import logging
import os
import random
import re
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
    stream=sys.stderr,
)
log = logging.getLogger("doge-collector")

# ---------------------------------------------------------------------------
# ElectrumX servers
# ---------------------------------------------------------------------------
ELECTRUM_SERVERS: List[Tuple[str, int, bool]] = [
    ("electrum1.cipig.net", 10060, False),
    ("electrum2.cipig.net", 10060, False),
    ("electrum3.cipig.net", 10060, False),
    ("electrum1.cipig.net", 10061, True),
    ("electrum2.cipig.net", 10061, True),
    ("electrum3.cipig.net", 10061, True),
    ("doge.not.fyi",        50002, True),
]

ELEC_PROTO        = "1.4"
ELEC_CONN_TO      = 15
ELEC_TIMEOUT      = 30
ELEC_STREAM_LIMIT = 8 * 1024 * 1024

CONCURRENCY  = 8    # BUG-D3 FIX: was 30
CHUNK        = 40   # BUG-D3 FIX: was 200
REST_TIMEOUT = 30   # BUG-D4 FIX: was 15; overridable via --rest-timeout

HTTP_RETRIES     = 3
HTTP_RETRY_DELAY = 1.0   # seconds; doubles each attempt

BLOCKCYPHER_PAGE_SLEEP = 0.6   # seconds

COINBASE_TXID = "0" * 64

_SSL_CTX: Optional[ssl.SSLContext] = None


def _get_ssl_ctx() -> ssl.SSLContext:
    global _SSL_CTX
    if _SSL_CTX is None:
        _SSL_CTX = ssl.create_default_context()
        _SSL_CTX.check_hostname = False
        _SSL_CTX.verify_mode    = ssl.CERT_NONE
    return _SSL_CTX


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------------------
# Varint
# ---------------------------------------------------------------------------

def _rd_vi(d: bytes, p: int) -> Tuple[int, int]:
    if p >= len(d): return -1, p
    b = d[p]
    if b < 0xFD:                     return b, p + 1
    if b == 0xFD and p + 3 <= len(d): return struct.unpack_from("<H", d, p + 1)[0], p + 3
    if b == 0xFE and p + 5 <= len(d): return struct.unpack_from("<I", d, p + 1)[0], p + 5
    if b == 0xFF and p + 9 <= len(d): return struct.unpack_from("<Q", d, p + 1)[0], p + 9
    return -1, p


def _varint(n: int) -> bytes:
    if n < 0xFD:        return bytes([n])
    if n <= 0xFFFF:     return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


# ---------------------------------------------------------------------------
# txid
# ---------------------------------------------------------------------------

def compute_txid(raw: bytes) -> str:
    return sha256d(raw)[::-1].hex()


# ---------------------------------------------------------------------------
# Transaction parser
# ---------------------------------------------------------------------------

def parse_tx(raw: bytes) -> Optional[Dict[str, Any]]:
    if len(raw) < 10: return None
    try:
        p = 0
        ver = struct.unpack_from("<i", raw, p)[0]; p += 4
        ic, p = _rd_vi(raw, p)
        if ic < 0 or ic > 50_000: return None
        inputs = []
        for _ in range(ic):
            if p + 36 > len(raw): return None
            ph = raw[p:p + 32][::-1].hex(); p += 32
            pn = struct.unpack_from("<I", raw, p)[0]; p += 4
            sl, p = _rd_vi(raw, p)
            if sl < 0 or sl > 500_000 or p + sl > len(raw): return None
            sc = raw[p:p + sl]; p += sl
            if p + 4 > len(raw): return None
            sq = struct.unpack_from("<I", raw, p)[0]; p += 4
            inputs.append({"prev_hash": ph, "prev_n": pn, "script": sc, "seq": sq})
        oc, p = _rd_vi(raw, p)
        if oc < 0 or oc > 50_000: return None
        outputs = []
        for _ in range(oc):
            if p + 8 > len(raw): return None
            val = struct.unpack_from("<q", raw, p)[0]; p += 8
            if val < 0: return None
            sl, p = _rd_vi(raw, p)
            if sl < 0 or sl > 500_000 or p + sl > len(raw): return None
            sc = raw[p:p + sl]; p += sl
            outputs.append({"value": val, "script": sc})
        # BUG-D-NEW-22 FIX: relaxed locktime check
        if p + 4 > len(raw): return None
        lt = struct.unpack_from("<I", raw, p)[0]
        return {"version": ver, "inputs": inputs, "outputs": outputs, "locktime": lt}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Base58Check / address helpers
# ---------------------------------------------------------------------------

_B58  = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58I = {c: i for i, c in enumerate(_B58)}
_ADDR_RE = re.compile(r'^[DA9][1-9A-HJ-NP-Za-km-z]{25,33}$')


def b58decode_check(addr: str) -> Optional[bytes]:
    if not addr or not _ADDR_RE.match(addr): return None
    leading = len(addr) - len(addr.lstrip("1"))
    n = 0
    for c in addr:
        v = _B58I.get(c)
        if v is None: return None
        n = n * 58 + v
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    full = b"\x00" * leading + n_bytes
    if len(full) != 25: return None
    body, ck = full[:21], full[21:]
    if sha256d(body)[:4] != ck: return None
    return body


def is_valid_doge_address(addr: str) -> bool:
    body = b58decode_check(addr)
    return body is not None and body[0] in (0x1E, 0x16)


def addr_to_scriptpubkey(addr: str) -> Optional[bytes]:
    body = b58decode_check(addr)
    if not body or len(body) != 21: return None
    ver, h160 = body[0], body[1:21]
    if ver == 0x1E: return bytes([0x76, 0xA9, 0x14]) + h160 + bytes([0x88, 0xAC])
    if ver == 0x16: return bytes([0xA9, 0x14]) + h160 + bytes([0x87])
    return None


def scriptpubkey_to_scripthash(spk: bytes) -> str:
    return hashlib.sha256(spk).digest()[::-1].hex()


# ---------------------------------------------------------------------------
# Hex-file cache
# ---------------------------------------------------------------------------

_TXID_RE_LOWER = re.compile(r'^[0-9a-f]{64}$')


def _load_cached_hex(fpath: str, txid: str) -> Optional[str]:
    try:
        with open(fpath, "r", encoding="ascii") as hf:
            raw_hex = hf.read().strip()
        raw_bytes = bytes.fromhex(raw_hex)
        if compute_txid(raw_bytes) != txid:
            log.warning("Cache hash mismatch for %s; will re-fetch.", txid)
            return None
        return raw_hex
    except (OSError, ValueError):
        return None


def _load_hex_dir_verified(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not os.path.isdir(path): return out
    for fn in os.listdir(path):
        if not fn.endswith(".hex"): continue
        txid = fn[:-4].lower()
        if not _TXID_RE_LOWER.match(txid): continue
        raw_hex = _load_cached_hex(os.path.join(path, fn), txid)
        if raw_hex is not None:
            out[txid] = raw_hex
    return out


def _save_hex(directory: str, txid: str, raw_hex: str) -> None:
    fpath = os.path.join(directory, f"{txid}.hex")
    if os.path.isfile(fpath): return
    try:
        with open(fpath, "w", encoding="ascii") as hf:
            hf.write(raw_hex.strip() + "\n")
    except OSError as e:
        log.warning("Could not cache %s: %s", txid, e)


# ---------------------------------------------------------------------------
# REST helpers with global rate limiting
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: int = 0) -> Optional[bytes]:
    if timeout == 0:
        timeout = REST_TIMEOUT
    delay = HTTP_RETRY_DELAY
    for attempt in range(HTTP_RETRIES):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "doge-collector/3.1 (vulnerability-research)"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503):
                wait = delay * (2 ** attempt) + random.uniform(0, 1.0)
                log.debug("HTTP %d for %s; back-off %.1fs (attempt %d/%d)",
                          exc.code, url, wait, attempt + 1, HTTP_RETRIES)
                time.sleep(wait)
            else:
                log.debug("HTTP %d for %s (no retry)", exc.code, url)
                return None
        except Exception as exc:
            if attempt < HTTP_RETRIES - 1:
                wait = delay * (2 ** attempt) + random.uniform(0, 0.5)
                log.debug("HTTP GET %s attempt %d/%d: %s (retry in %.1fs)",
                          url, attempt + 1, HTTP_RETRIES, exc, wait)
                time.sleep(wait)
            else:
                log.debug("HTTP GET %s: %s (giving up)", url, exc)
    return None


def _rest_get_raw_tx(txid: str) -> Optional[str]:
    # BlockCypher
    body = _http_get(
        f"https://api.blockcypher.com/v1/doge/main/txs/{txid}?includeHex=true")
    if body:
        try:
            d = json.loads(body)
            h = d.get("hex", "")
            if h and compute_txid(bytes.fromhex(h)) == txid: return h
        except (json.JSONDecodeError, ValueError): pass

    # SoChain
    body = _http_get(f"https://sochain.com/api/v2/get_tx/DOGE/{txid}")
    if body:
        try:
            d = json.loads(body)
            h = d.get("data", {}).get("tx_hex", "")
            if h and compute_txid(bytes.fromhex(h)) == txid: return h
        except (json.JSONDecodeError, ValueError): pass

    # DogeChain
    body = _http_get(f"https://dogechain.info/api/v1/transaction/{txid}")
    if body:
        try:
            d = json.loads(body)
            h = d.get("transaction", {}).get("hex", "") or d.get("hex", "")
            if h and compute_txid(bytes.fromhex(h)) == txid: return h
        except (json.JSONDecodeError, ValueError): pass

    # Bitaps
    body = _http_get(
        f"https://api.bitaps.com/doge/v1/blockchain/transaction/{txid}")
    if body:
        try:
            d = json.loads(body)
            h = d.get("data", {}).get("rawTx", "")
            if h and compute_txid(bytes.fromhex(h)) == txid: return h
        except (json.JSONDecodeError, ValueError): pass

    # Blockchair
    body = _http_get(
        f"https://api.blockchair.com/dogecoin/raw/transaction/{txid}")
    if body:
        try:
            d = json.loads(body)
            h = (d.get("data", {}).get(txid, {}).get("raw_transaction", "") or
                 d.get("data", {}).get(txid.upper(), {}).get("raw_transaction", ""))
            if h and compute_txid(bytes.fromhex(h)) == txid: return h
        except (json.JSONDecodeError, ValueError): pass

    return None


def _blockcypher_get_history(
    address: str, max_pages: int = 50
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    before: Optional[int] = None
    for page_num in range(max_pages):
        url = (f"https://api.blockcypher.com/v1/doge/main/addrs/{address}"
               f"?limit=2000&omitWalletAddresses=true")
        if before is not None: url += f"&before={before}"
        body = _http_get(url)
        if not body: break
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            break
        txrefs = data.get("txrefs", []) + data.get("unconfirmed_txrefs", [])
        if not txrefs: break
        page_added = 0
        min_height: Optional[int] = None
        for ref in txrefs:
            txhash = ref.get("tx_hash", "")
            height = ref.get("block_height", 0) or 0
            if txhash and txhash not in seen:
                seen.add(txhash)
                results.append({"tx_hash": txhash, "height": height})
                page_added += 1
            if height and (min_height is None or height < min_height):
                min_height = height
        if page_added == 0 or not data.get("hasMore"): break
        if min_height is None or min_height <= 1: break
        before = min_height
        if page_num + 1 < max_pages:
            time.sleep(BLOCKCYPHER_PAGE_SLEEP)
    return results


def _rest_get_history(
    address: str, max_pages: int = 50
) -> List[Dict[str, Any]]:
    results = _blockcypher_get_history(address, max_pages=max_pages)
    if results:
        log.info("REST history: %d txs via BlockCypher", len(results))
        return results

    # SoChain
    body = _http_get(f"https://sochain.com/api/v2/address/DOGE/{address}")
    if body:
        try:
            data = json.loads(body)
            seen2: Set[str] = set()
            for tx in data.get("data", {}).get("txs", []):
                txhash = tx.get("txid", "")
                if txhash and txhash not in seen2:
                    seen2.add(txhash)
                    results.append({"tx_hash": txhash,
                                    "height": int(tx.get("block_no") or 0)})
            if results:
                log.info("REST history: %d txs via SoChain", len(results))
                return results
        except (json.JSONDecodeError, KeyError, ValueError): pass

    # DogeChain
    seen3: Set[str] = set()
    for page in range(1, 11):
        body = _http_get(
            f"https://dogechain.info/api/v1/address/transactions/{address}/{page}")
        if not body: break
        try:
            data = json.loads(body)
            txs = data.get("transactions", [])
            if not txs: break
            for tx in txs:
                txhash = tx.get("hash", "") or tx.get("tx_hash", "")
                height = int(tx.get("block_index") or tx.get("height") or 0)
                if txhash and txhash not in seen3:
                    seen3.add(txhash)
                    results.append({"tx_hash": txhash, "height": height})
        except (json.JSONDecodeError, KeyError, ValueError):
            break

    if results:
        log.info("REST history: %d txs via DogeChain", len(results))
        return results

    log.warning("REST: no history found for %s.", address)
    return []


# ---------------------------------------------------------------------------
# Rate-limited async REST wrapper with global rate limiting
# ---------------------------------------------------------------------------

class RestLimiter:
    def __init__(self) -> None:
        self._sem: Optional[asyncio.Semaphore] = None
        self._last_call: float = 0.0
        self._min_interval: float = 0.15   # global rate limit ~6.7 req/sec

    def _get_sem(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(3)
        return self._sem

    async def get_raw_tx(self, txid: str) -> Optional[str]:
        async with self._get_sem():
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_call = asyncio.get_event_loop().time()
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(None, _rest_get_raw_tx, txid)
            if res is not None:
                await asyncio.sleep(0.34)   # per‑source cooling
            return res

    async def get_history(
        self, address: str, max_pages: int = 50
    ) -> List[Dict[str, Any]]:
        async with self._get_sem():
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_call = asyncio.get_event_loop().time()
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(
                None, _rest_get_history, address, max_pages)
            if res:
                await asyncio.sleep(0.34)
            return res or []


REST = RestLimiter()


# ---------------------------------------------------------------------------
# ElectrumX connection (unchanged, as provided by user)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PrevoutRef:
    txid: str
    vout: int


class ElectrumConn:
    def __init__(self, host: str, port: int, use_ssl: bool) -> None:
        self.host = host; self.port = port; self.use_ssl = use_ssl
        self.r: Optional[asyncio.StreamReader] = None
        self.w: Optional[asyncio.StreamWriter] = None
        self.pending: Dict[int, asyncio.Future] = {}
        self._id = 0
        self._lock = asyncio.Lock()
        self._alive = False
        self._recv_task: Optional[asyncio.Task] = None

    async def connect(self) -> bool:
        try:
            ctx = _get_ssl_ctx() if self.use_ssl else None
            self.r, self.w = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port,
                                        ssl=ctx, limit=ELEC_STREAM_LIMIT),
                timeout=ELEC_CONN_TO)
            self._alive = True
            self._recv_task = asyncio.create_task(self._recv_loop())
            result = await self.call("server.version",
                                     ["doge-collector/3.1", ELEC_PROTO])
            if not isinstance(result, list) or len(result) < 2:
                self.close(); return False
            if int(str(result[1]).split(".")[0]) < int(ELEC_PROTO.split(".")[0]):
                self.close(); return False
            return True
        except Exception as exc:
            log.debug("connect %s:%d: %s", self.host, self.port, exc)
            self.close(); return False

    async def _recv_loop(self) -> None:
        try:
            while self._alive and self.r:
                try:
                    line = await asyncio.wait_for(
                        self.r.readuntil(b"\n"), timeout=60)
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    raise
                except (asyncio.LimitOverrunError, ValueError):
                    self._alive = False; break
                except (EOFError, ConnectionResetError, asyncio.IncompleteReadError):
                    break
                if not line: break
                try:
                    msg = json.loads(line.decode(errors="replace").strip())
                    mid = msg.get("id")
                    if mid in self.pending:
                        fut = self.pending.pop(mid)
                        if not fut.done():
                            if msg.get("error"):
                                fut.set_exception(
                                    RuntimeError(str(msg["error"])))
                            else:
                                fut.set_result(msg.get("result"))
                except Exception:
                    pass
        except asyncio.CancelledError:
            pass
        finally:
            self._alive = False
            for fut in self.pending.values():
                if not fut.done():
                    fut.set_exception(ConnectionError("disconnected"))
            self.pending.clear()

    async def call(self, method: str, params: List[Any]) -> Any:
        if not self._alive or not self.w:
            raise ConnectionError("not connected")
        async with self._lock:
            self._id += 1; rid = self._id
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            self.pending[rid] = fut
            msg = (json.dumps({"id": rid, "method": method,
                               "params": params}) + "\n").encode()
            try:
                self.w.write(msg); await self.w.drain()
            except Exception:
                self.pending.pop(rid, None)
                if not fut.done(): fut.cancel()
                raise
        try:
            return await asyncio.wait_for(fut, timeout=ELEC_TIMEOUT)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            self.pending.pop(rid, None); raise

    @property
    def alive(self) -> bool:
        return self._alive

    def close(self) -> None:
        self._alive = False
        if self.w:
            with contextlib.suppress(Exception): self.w.close()
        if self._recv_task and not self._recv_task.done():
            self._recv_task.cancel()

    async def aclose(self) -> None:
        self.close()
        if self.w:
            with contextlib.suppress(Exception): await self.w.wait_closed()


class ElectrumPool:
    def __init__(self) -> None:
        self.conns: List[ElectrumConn] = []

    async def start(self, max_conns: int = 4) -> int:
        async def try_connect(h: str, p: int, s: bool) -> Optional[ElectrumConn]:
            c = ElectrumConn(h, p, s)
            ok = await c.connect()
            if ok:
                log.info("ElectrumX OK: %s:%d ssl=%s", h, p, s)
                return c
            return None

        results = await asyncio.gather(
            *[try_connect(h, p, s) for h, p, s in ELECTRUM_SERVERS],
            return_exceptions=True)
        for res in results:
            if isinstance(res, Exception): continue
            if res is not None and len(self.conns) < max_conns:
                self.conns.append(res)
            elif res is not None:
                await res.aclose()
        return len(self.conns)

    def pick(self) -> Optional[ElectrumConn]:
        alive = [c for c in self.conns if c.alive]
        return random.choice(alive) if alive else None

    async def call(self, method: str, params: List[Any], tries: int = 5) -> Any:
        last: Exception = ConnectionError("No servers alive")
        base_delay = 0.5
        for attempt in range(tries):
            c = self.pick()
            if not c:
                wait = base_delay * (2 ** attempt) + random.uniform(
                    0, base_delay * 0.3)
                await asyncio.sleep(min(wait, 10.0))
                continue
            try:
                return await c.call(method, params)
            except Exception as e:
                last = e
                wait = base_delay * (2 ** attempt) * 0.5 + random.uniform(
                    0, 0.5)
                await asyncio.sleep(min(wait, 10.0))
        raise RuntimeError(f"Electrum call failed {tries}x {method}: {last}")

    async def get_history(self, sh: str) -> List[Dict[str, Any]]:
        r = await self.call("blockchain.scripthash.get_history", [sh])
        return r if isinstance(r, list) else []

    async def get_raw_tx(self, txid: str) -> str:
        r = await self.call("blockchain.transaction.get", [txid, False])
        return r if isinstance(r, str) else ""

    def close(self) -> None:
        for c in self.conns: c.close()

    async def aclose(self) -> None:
        for c in self.conns: await c.aclose()


# ---------------------------------------------------------------------------
# Address parser, fetch helper, and core collector (unchanged except rate limiting)
# ---------------------------------------------------------------------------

def _find_doge_addr_in_row(row: List[str]) -> Optional[str]:
    for cell in row:
        candidate = cell.strip()
        if candidate and is_valid_doge_address(candidate):
            return candidate
    return None


def read_addresses(input_val: str) -> List[str]:
    raw: List[str] = []
    if os.path.isfile(input_val):
        ext = os.path.splitext(input_val)[1].lower()
        with open(input_val, "r", encoding="utf-8-sig") as f:
            if ext == ".csv":
                reader = csv.reader(f)
                for row in reader:
                    if not row: continue
                    first = row[0].strip().lower()
                    if first in ("address", "addr", "txid", "pubkey", "#", ""):
                        continue
                    addr = _find_doge_addr_in_row(row)
                    if addr: raw.append(addr)
            else:
                for line in f:
                    line = line.split("#")[0].strip()
                    if not line: continue
                    for part in line.split(","):
                        part = part.strip()
                        if part: raw.append(part)
    else:
        for part in input_val.split(","):
            part = part.strip()
            if part: raw.append(part)

    seen: Set[str] = set()
    valid: List[str] = []
    skipped = 0
    for a in raw:
        a = a.strip()
        if not a or a in seen: continue
        if not is_valid_doge_address(a):
            log.warning("Invalid Dogecoin address skipped: %s", a)
            skipped += 1; continue
        seen.add(a); valid.append(a)
    if skipped:
        log.warning("Skipped %d invalid address(es).", skipped)
    return valid


async def _fetch_tx_with_retry(
    txid: str,
    raw_map: Dict[str, str],
    sem: asyncio.Semaphore,
    pool: ElectrumPool,
    use_rest: bool,
    error_counter: Dict[str, int],
    error_key: str,
    label: str = "tx",
) -> None:
    async with sem:
        delay = 1.0
        for attempt in range(5):
            try:
                raw = ""
                if not use_rest:
                    try:
                        raw = await pool.get_raw_tx(txid)
                    except Exception:
                        raw = ""
                if not raw:
                    raw = await REST.get_raw_tx(txid) or ""
                if not raw:
                    raise ValueError("empty from all sources")
                rb = bytes.fromhex(raw)
                if compute_txid(rb) != txid:
                    raise ValueError("txid mismatch")
                raw_map[txid] = raw
                return
            except Exception as exc:
                log.debug("fetch_%s %s #%d: %s", label, txid, attempt, exc)
                if attempt < 4:
                    jitter = random.uniform(0, delay * 0.3)
                    await asyncio.sleep(delay + jitter)
                    delay = min(delay * 2, 30.0)
        error_counter[error_key] = error_counter.get(error_key, 0) + 1


async def collect(
    address: str,
    outdir: str,
    pool: ElectrumPool,
    use_rest_global: bool,
    concurrency: int = CONCURRENCY,
    chunk: int = CHUNK,
    max_pages: int = 50,
) -> Dict[str, Any]:

    os.makedirs(outdir, exist_ok=True)
    tx_hex_dir   = os.path.join(outdir, "txs_raw")
    prev_hex_dir = os.path.join(outdir, "prevouts_raw")
    os.makedirs(tx_hex_dir,   exist_ok=True)
    os.makedirs(prev_hex_dir, exist_ok=True)

    spk = addr_to_scriptpubkey(address)
    if spk is None:
        log.error("Cannot derive scriptPubKey for %s.", address)
        return {"address": address, "error": "invalid_address"}
    sh = scriptpubkey_to_scripthash(spk)

    log.info("Address     : %s", address)
    log.info("scriptPubKey: %s", spk.hex())
    log.info("scripthash  : %s", sh)

    raw_map:      Dict[str, str] = _load_hex_dir_verified(tx_hex_dir)
    prev_raw_map: Dict[str, str] = _load_hex_dir_verified(prev_hex_dir)
    log.info("Cache: %d spend txs, %d prevout txs", len(raw_map), len(prev_raw_map))

    use_rest = use_rest_global

    hist: List[Dict[str, Any]] = []
    if not use_rest:
        try:
            hist = await pool.get_history(sh)
        except Exception as exc:
            log.warning("ElectrumX history failed (%s); falling back to REST.", exc)
            use_rest = True
    if use_rest or not hist:
        hist = await REST.get_history(address, max_pages=max_pages)
        if not hist:
            log.warning("No history for %s from any source.", address)

    seen_txids: Set[str] = set()
    txids: List[str] = []
    heights: Dict[str, int] = {}
    for h in hist:
        if not isinstance(h, dict): continue
        txhash = h.get("tx_hash", "")
        if not txhash or txhash in seen_txids: continue
        seen_txids.add(txhash); txids.append(txhash)
        heights[txhash] = int(h.get("height") or 0)

    log.info("History: %d unique transactions", len(txids))
    if not txids:
        summary = {
            "address": address, "scripthash": sh, "txids_total": 0,
            "inputs_rows": 0,
            "finished_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        with open(os.path.join(outdir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2)
        return summary

    txids_csv = os.path.join(outdir, "txids.csv")
    with open(txids_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["address", "txid", "height"])
        for t in txids: w.writerow([address, t, heights.get(t, 0)])

    fetch_errors: Dict[str, int] = {"spend": 0, "prevout": 0}
    sem  = asyncio.Semaphore(concurrency)
    sem2 = asyncio.Semaphore(concurrency)
    to_fetch = [t for t in txids if t not in raw_map]
    log.info("Spend txs: %d cached, %d to fetch", len(raw_map), len(to_fetch))

    for i in range(0, len(to_fetch), chunk):
        ch = to_fetch[i:i + chunk]
        await asyncio.gather(*[
            asyncio.create_task(_fetch_tx_with_retry(
                t, raw_map, sem, pool, use_rest,
                fetch_errors, "spend", "spend"))
            for t in ch
        ])
        done = min(i + chunk, len(to_fetch))
        log.info("Spend: %d/%d  ok=%d  err=%d",
                 done, len(to_fetch), len(raw_map), fetch_errors["spend"])

    for txid, raw_hex in raw_map.items():
        _save_hex(tx_hex_dir, txid, raw_hex)

    missing_spend = [t for t in txids if t not in raw_map]

    prevouts_needed: Set[PrevoutRef] = set()
    per_input_rows: List[Dict[str, Any]] = []
    loop_parse_fails = 0
    for txid, raw_hex in raw_map.items():
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            loop_parse_fails += 1; continue
        tx = parse_tx(raw)
        if not tx:
            loop_parse_fails += 1; continue
        for vin_idx, vin in enumerate(tx["inputs"]):
            prev_txid = vin["prev_hash"]
            prev_vout = int(vin["prev_n"])
            if not prev_txid or prev_txid == COINBASE_TXID:
                continue
            prevouts_needed.add(PrevoutRef(prev_txid, prev_vout))
            per_input_rows.append({
                "spend_txid":    txid,
                "spend_vin":     vin_idx,
                "prev_txid":     prev_txid,
                "prev_vout":     prev_vout,
                "scriptSig_hex": vin["script"].hex(),
                "sequence":      vin["seq"],
            })

    prev_txids = sorted({p.txid for p in prevouts_needed
                         if p.txid and p.txid != COINBASE_TXID})
    log.info("Prevout txids needed: %d", len(prev_txids))
    if loop_parse_fails:
        log.warning("Spend tx parse failures (row loop): %d", loop_parse_fails)

    prev_to_fetch = [t for t in prev_txids if t not in prev_raw_map]
    log.info("Prevout txs: %d cached, %d to fetch",
             len(prev_raw_map), len(prev_to_fetch))

    for i in range(0, len(prev_to_fetch), chunk):
        ch = prev_to_fetch[i:i + chunk]
        await asyncio.gather(*[
            asyncio.create_task(_fetch_tx_with_retry(
                t, prev_raw_map, sem2, pool, use_rest,
                fetch_errors, "prevout", "prevout"))
            for t in ch
        ])
        done = min(i + chunk, len(prev_to_fetch))
        log.info("Prevout: %d/%d  ok=%d  err=%d",
                 done, len(prev_to_fetch),
                 len(prev_raw_map), fetch_errors["prevout"])

    for txid, raw_hex in prev_raw_map.items():
        _save_hex(prev_hex_dir, txid, raw_hex)

    prevout_info: Dict[Tuple[str, int], Tuple[int, str]] = {}
    for ptxid, praw in prev_raw_map.items():
        try:
            raw = bytes.fromhex(praw)
        except ValueError:
            continue
        tx = parse_tx(raw)
        if not tx: continue
        for vout, o in enumerate(tx["outputs"]):
            prevout_info[(ptxid, vout)] = (int(o["value"]), o["script"].hex())

    out_csv = os.path.join(outdir, "inputs_enriched.csv")
    fieldnames = [
        "address", "spend_txid", "spend_vin", "prev_txid", "prev_vout",
        "prevout_value_sat", "prevout_scriptpubkey_hex",
        "scriptSig_hex", "sequence",
    ]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in per_input_rows:
            key  = (row["prev_txid"], int(row["prev_vout"]))
            info = prevout_info.get(key)
            w.writerow({
                "address":                  address,
                "spend_txid":               row["spend_txid"],
                "spend_vin":                row["spend_vin"],
                "prev_txid":                row["prev_txid"],
                "prev_vout":                row["prev_vout"],
                "prevout_value_sat":        info[0] if info else "",
                "prevout_scriptpubkey_hex": info[1] if info else "",
                "scriptSig_hex":            row["scriptSig_hex"],
                "sequence":                 row["sequence"],
            })

    summary: Dict[str, Any] = {
        "address":                address,
        "scripthash":             sh,
        "txids_total":            len(txids),
        "raw_txs_downloaded":     len(raw_map),
        "raw_txs_missing":        len(missing_spend),
        "missing_spend_txids":    missing_spend[:200],
        "raw_txs_fetch_errors":   fetch_errors["spend"],
        "tx_parse_fail_in_loop":  loop_parse_fails,
        "prevout_txids_needed":   len(prev_txids),
        "prevout_raw_downloaded": len(prev_raw_map),
        "prevout_fetch_errors":   fetch_errors["prevout"],
        "inputs_rows":            len(per_input_rows),
        "electrum_connected":     sum(1 for c in pool.conns if c.alive),
        "rest_fallback_used":     use_rest,
        "finished_at_utc":        dt.datetime.now(dt.timezone.utc).isoformat(),
        "outputs": {
            "txids_csv":        txids_csv,
            "inputs_enriched":  out_csv,
            "txs_raw_dir":      tx_hex_dir,
            "prevouts_raw_dir": prev_hex_dir,
        },
    }
    with open(os.path.join(outdir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    log.info("Done %s: %d inputs, %d prevouts resolved",
             address, len(per_input_rows), len(prevout_info))
    return summary


# ---------------------------------------------------------------------------
# Multi-address runner and CLI
# ---------------------------------------------------------------------------

async def run_all(
    inputs: List[str],
    base_outdir: str,
    no_electrum: bool = False,
    concurrency: int = CONCURRENCY,
    chunk: int = CHUNK,
    max_pages: int = 50,
) -> None:
    os.makedirs(base_outdir, exist_ok=True)
    pool = ElectrumPool()
    multi = len(inputs) > 1
    all_summaries: List[Dict[str, Any]] = []
    try:
        if no_electrum:
            log.info("ElectrumX disabled by --no-electrum.")
            use_rest_global = True
        else:
            n_conn = await pool.start(max_conns=4)
            log.info("ElectrumX: %d/%d connected", n_conn, len(ELECTRUM_SERVERS))
            use_rest_global = (n_conn == 0)
            if use_rest_global:
                log.warning("No ElectrumX reachable; REST-only mode.")

        for idx, addr in enumerate(inputs, 1):
            addr_outdir = os.path.join(base_outdir, addr) if multi else base_outdir
            log.info("─── [%d/%d] %s ───", idx, len(inputs), addr)
            try:
                summary = await collect(
                    addr, addr_outdir, pool,
                    use_rest_global, concurrency, chunk,
                    max_pages=max_pages)
                all_summaries.append(summary)
            except Exception as e:
                log.error("Failed %s: %s", addr, e)
                all_summaries.append({"address": addr, "error": str(e)})

        if multi:
            master_csv = os.path.join(base_outdir, "addresses_processed.csv")
            fields = [
                "address", "txids_total", "inputs_rows",
                "raw_txs_downloaded", "prevout_raw_downloaded",
                "tx_parse_fail_in_loop", "error", "finished_at_utc",
            ]
            with open(master_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                for s in all_summaries:
                    w.writerow({k: s.get(k, "") for k in fields})
            log.info("Master index: %s", master_csv)
            with open(os.path.join(base_outdir, "all_summaries.json"),
                      "w", encoding="utf-8") as f:
                json.dump(all_summaries, f, indent=2)
    finally:
        await pool.aclose()


def main() -> None:
    global REST_TIMEOUT
    ap = argparse.ArgumentParser(
        description="Dogecoin blockchain data collector  (Stage 1 of 3).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python data.py D7Y55D...                    ./out
  python data.py D7Y55...,DAbc12...           ./out
  python data.py addresses.csv                ./out
  python data.py addr_list.txt                ./out
  python data.py placeholder ./out --addresses D7Y55...,DAbc...
  python data.py addresses.csv ./out --no-electrum --debug
        """)
    ap.add_argument("input",
                    help="Dogecoin address, comma-separated list, or CSV/TXT file")
    ap.add_argument("outdir", help="Output directory")
    ap.add_argument("--addresses", metavar="ADDR,...",
                    help="Additional comma-separated addresses")
    ap.add_argument("--no-electrum", action="store_true",
                    help="Use REST APIs only (skip ElectrumX)")
    ap.add_argument("--concurrency", type=int, default=CONCURRENCY,
                    metavar="N",
                    help=f"Max concurrent fetches (default {CONCURRENCY})")
    ap.add_argument("--chunk", type=int, default=CHUNK,
                    metavar="N",
                    help=f"Batch size per gather() call (default {CHUNK})")
    ap.add_argument("--max-pages", type=int, default=50,
                    metavar="N",
                    help="Max BlockCypher pagination pages (default 50)")
    ap.add_argument("--rest-timeout", type=int, default=REST_TIMEOUT,
                    metavar="SEC",
                    help=f"REST request timeout in seconds (default {REST_TIMEOUT})")
    ap.add_argument("--debug", action="store_true",
                    help="Enable DEBUG logging")
    args = ap.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        log.setLevel(logging.DEBUG)

    REST_TIMEOUT = args.rest_timeout

    addrs: List[str] = []
    if args.addresses:
        addrs.extend(read_addresses(args.addresses))
    for a in read_addresses(args.input):
        if a not in addrs:
            addrs.append(a)

    if not addrs:
        print("No valid Dogecoin addresses found.", file=sys.stderr)
        sys.exit(1)

    log.info("Processing %d address(es):", len(addrs))
    for i, a in enumerate(addrs, 1):
        log.info("  [%d] %s", i, a)

    try:
        asyncio.run(run_all(
            addrs, args.outdir,
            no_electrum=args.no_electrum,
            concurrency=args.concurrency,
            chunk=args.chunk,
            max_pages=args.max_pages,
        ))
    except KeyboardInterrupt:
        log.info("Interrupted.")
        sys.exit(0)
    except Exception as exc:
        log.error("Fatal: %s", exc, exc_info=args.debug)
        sys.exit(1)


if __name__ == "__main__":
    main()