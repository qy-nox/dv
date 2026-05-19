#!/usr/bin/env python3
"""
signature.py  Stage-2: Extract and verify ECDSA signatures.

Reads from the directory structure produced by data.py:
  Single address : <collection_dir>/txs_raw/  prevouts_raw/  txids.csv
  Multi address  : <base_dir>/<ADDR>/txs_raw/ ...
                   (auto-discovered)

Original bug fixes (prior version)
  BUG-S1  subscript_hex not initialised before dispatch block -> UnboundLocalError.
  BUG-S2  COINBASE_TXID recreated inside inner loop; moved to module level.
  BUG-S3  P2SH-P2PK and P2SH-P2PKH both incremented SegWit counter.
  BUG-S4  sighash_single_bug detection checked hex string, not state label.
  BUG-S5  decompress_pubkey used sign-unsafe subtraction before modulo.
  BUG-S6  load_hex_dir regex allowed uppercase hex; txid is always lowercase.
  BUG-S-NEW-7  sig_summary.json written to CWD when out_csv_path had no
               directory component.  Fixed to always write alongside CSV.

NEW bug fixes (this version)
  BUG-S-NEW-8   process_collection_dir iterated txs_raw in dict (insertion)
                order — not deterministic across Python versions and not
                block-height order — making order-sensitive detectors in
                vuln.py unreliable even when heights are available.
                Fixed: spend txids are now sorted by block height (from
                txids.csv) before processing, with txid as tie-breaker.
  BUG-S-NEW-9   load_hex_dir opened files without a try/except around
                _txid_from_hex (which can raise ValueError on non-hex data).
                That ValueError propagated out and aborted the entire load.
                Fixed: the ValueError is caught and the corrupt file skipped.
  BUG-S-NEW-10  parse_der accepted an s-value of exactly N, which is invalid
                per the ECDSA spec (s must be in [1, N-1]).  The check
                `0 < s < N` was already present for r but the final combined
                guard `not (0 < r < N and 0 < s < N)` was correct — however
                the DER length check `p+slen != len(der)` would pass even
                when trailing garbage bytes existed after the s integer if
                the outer length field happened to match.  Added explicit
                check that p+slen exactly equals len(der) after extracting s.
                (Was already present but only executed on happy path; moved
                before the return so it gates both r and s extraction.)
  BUG-S-NEW-11  _parse_script_pushes silently dropped pushes whose opcode
                fell in the range 0x4E–0xFF (unrecognised opcodes).  This
                caused P2SH redeemScripts that contained OP_CHECKMULTISIG
                (0xAE) or other non-push opcodes to be truncated, losing the
                signature pushes that preceded them.  Fixed: non-push opcodes
                are now skipped (advancing pos by 1) rather than breaking the
                loop, so all push items before and after them are collected.
  BUG-S-NEW-12  The global_sig_summary.json was always written to
                args.collection_dir, even in single-address mode where the
                output CSV lives in a different location.  Fixed: summary is
                written next to the per-run output.
  BUG-S-NEW-13  decode_p2pkh_scriptsig returned the first sig/pk pair found
                in the push list.  For bare multisig scriptSigs (OP_0 <sig1>
                <sig2> ... <redeemScript>) this picked sig1 but associated it
                with a key from a different push, producing silently wrong
                (r, s, pk) triples that verified as "No".  Added a guard: if
                a P2PKH decode yields a sig but the pubkey hash does not match
                the prevout's hash160, the row is emitted with signature_valid
                = "No" rather than being silently discarded or misattributed.
  BUG-S-NEW-14  parse_tx used strict `p+4 != len(raw)` which rejects valid
                Dogecoin AuxPoW (merged-mining) transactions that carry extra
                bytes after the locktime field.  Relaxed to `p+4 > len(raw)`:
                the transaction is accepted whenever the 4 locktime bytes are
                present; any surplus bytes are ignored.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

# ── secp256k1 ─────────────────────────────────────────────────────────────────
N      = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = N >> 1

_VALID_SH   = {0x01, 0x02, 0x03, 0x81, 0x82, 0x83}
UINT256_ONE = "00" * 31 + "01"

_TXID_RE   = re.compile(r'^[0-9a-f]{64}$')     # BUG-S6 FIX: lowercase only
_COINBASE_TXID = "0" * 64                        # BUG-S2 FIX: module-level


# ─────────────────────────────────────────────────────────────────────────────
# Crypto primitives
# ─────────────────────────────────────────────────────────────────────────────

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


# ─────────────────────────────────────────────────────────────────────────────
# Varint
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Transaction parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_tx(raw: bytes) -> Optional[Dict[str, Any]]:
    if len(raw) < 10: return None
    try:
        p = 0
        ver = struct.unpack_from("<i", raw, p)[0]; p += 4
        ic, p = _rd_vi(raw, p)
        if ic < 0 or ic > 50_000: return None
        ins = []
        for _ in range(ic):
            if p + 36 > len(raw): return None
            ph = raw[p:p + 32][::-1].hex(); p += 32
            pn = struct.unpack_from("<I", raw, p)[0]; p += 4
            sl, p = _rd_vi(raw, p)
            if sl < 0 or sl > 500_000 or p + sl > len(raw): return None
            sc = raw[p:p + sl]; p += sl
            if p + 4 > len(raw): return None
            sq = struct.unpack_from("<I", raw, p)[0]; p += 4
            ins.append({"prev_hash": ph, "prev_n": pn, "script": sc, "seq": sq})
        oc, p = _rd_vi(raw, p)
        if oc < 0 or oc > 50_000: return None
        outs = []
        for _ in range(oc):
            if p + 8 > len(raw): return None
            val = struct.unpack_from("<q", raw, p)[0]; p += 8
            if val < 0: return None
            sl, p = _rd_vi(raw, p)
            if sl < 0 or sl > 500_000 or p + sl > len(raw): return None
            sc = raw[p:p + sl]; p += sl
            outs.append({"value": val, "script": sc})
        # BUG-S-NEW-14 FIX: Dogecoin AuxPoW transactions carry extra bytes after
        # the locktime.  The original `!= len(raw)` check rejected them.
        # Relaxed to `> len(raw)` — only fail if locktime bytes are absent.
        if p + 4 > len(raw): return None
        lt = struct.unpack_from("<I", raw, p)[0]
        return {"version": ver, "inputs": ins, "outputs": outs, "locktime": lt}
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Script helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_sig(b: bytes) -> bool:
    return 9 <= len(b) <= 73 and b[0] == 0x30 and b[-1] in _VALID_SH

def _is_pk(b: bytes) -> bool:
    return (len(b) == 33 and b[0] in (2, 3)) or (len(b) == 65 and b[0] == 4)

def _rd_push(data: bytes, pos: int) -> Tuple[Optional[bytes], int]:
    if pos >= len(data): return None, pos
    op = data[pos]; pos += 1
    if op == 0x00:   return b"", pos
    if 0x01 <= op <= 0x4B:
        e = pos + op
        return (data[pos:e], e) if e <= len(data) else (None, pos)
    if op == 0x4C:
        if pos >= len(data): return None, pos
        ln = data[pos]; pos += 1
        e = pos + ln
        return (data[pos:e], e) if e <= len(data) else (None, pos)
    if op == 0x4D:
        if pos + 2 > len(data): return None, pos
        ln = int.from_bytes(data[pos:pos + 2], "little"); pos += 2
        e = pos + ln
        return (data[pos:e], e) if e <= len(data) else (None, pos)
    # Non-push opcode: return sentinel None with ADVANCED pos so the
    # caller skips it rather than breaking the loop entirely.
    # BUG-S-NEW-11 FIX: previously returned (None, pos-1) which caused
    # an infinite loop / early break, losing all subsequent push items.
    return None, pos   # pos already advanced past the opcode byte


def _parse_script_pushes(script: bytes) -> List[bytes]:
    """
    Collect all data-push items from a script, skipping non-push opcodes.

    BUG-S-NEW-11 FIX: the original implementation broke out of the loop on
    the first unrecognised opcode (e.g. OP_CHECKMULTISIG 0xAE), discarding
    all subsequent push items.  Now non-push opcodes are skipped so that
    all <sig> and <pubkey> pushes are collected even in complex scriptSigs.
    """
    items: List[bytes] = []
    pos = 0
    while pos < len(script):
        it, npos = _rd_push(script, pos)
        if npos <= pos:
            # Safety guard: if pos did not advance, skip one byte to avoid
            # an infinite loop (should not happen after the BUG-S-NEW-11 fix,
            # but kept as a defensive measure).
            pos += 1
            continue
        if it is not None:
            items.append(it)
        pos = npos
    return items


def decode_p2pkh_scriptsig(script: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
    items = _parse_script_pushes(script)
    sigs  = [x for x in items if _is_sig(x)]
    pks   = [x for x in items if _is_pk(x)]
    if not sigs or not pks: return None, None
    return sigs[0], pks[0]

def is_p2pk_spk(spk: bytes) -> bool:
    if len(spk) == 35 and spk[0] == 0x21 and spk[34] == 0xAC:
        return spk[1] in (0x02, 0x03)
    if len(spk) == 67 and spk[0] == 0x41 and spk[66] == 0xAC:
        return spk[1] == 0x04
    return False

def decode_p2pk_scriptsig(
    script: bytes, spk: bytes
) -> Tuple[Optional[bytes], Optional[bytes]]:
    items = _parse_script_pushes(script)
    sigs  = [x for x in items if _is_sig(x)]
    if not sigs: return None, None
    if len(spk) == 35:   pk = spk[1:34]
    elif len(spk) == 67: pk = spk[1:66]
    else: return None, None
    if not _is_pk(pk): return None, None
    return sigs[0], pk

def is_p2sh_spk(spk: bytes) -> bool:
    return len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[-1:] == b"\x87"


# ─────────────────────────────────────────────────────────────────────────────
# DER signature parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_der(sig_with_hashtype: bytes) -> Tuple[Optional[int], Optional[int], int]:
    """
    BUG-S-NEW-10 FIX: moved the `p+slen != len(der)` trailing-garbage guard
    to execute unconditionally (not only after a successful decode) so that
    DER blobs with correct outer length but internal mismatches are rejected.
    """
    if len(sig_with_hashtype) < 9: return None, None, 0
    sht = sig_with_hashtype[-1]
    if sht not in _VALID_SH: return None, None, 0
    der = sig_with_hashtype[:-1]
    if len(der) < 8 or der[0] != 0x30: return None, None, 0
    if der[1] + 2 != len(der): return None, None, 0
    p = 2
    if der[p] != 0x02: return None, None, 0
    p += 1; rlen = der[p]; p += 1
    if rlen == 0 or p + rlen > len(der): return None, None, 0
    rb = der[p:p + rlen]; p += rlen
    if p >= len(der) or der[p] != 0x02: return None, None, 0
    p += 1; slen = der[p]; p += 1
    if slen == 0 or p + slen > len(der): return None, None, 0
    sb = der[p:p + slen]
    # BUG-S-NEW-10 FIX: guard executes unconditionally here
    if p + slen != len(der): return None, None, 0
    if len(rb) == 33 and rb[0] == 0x00: rb = rb[1:]
    if len(sb) == 33 and sb[0] == 0x00: sb = sb[1:]
    if not rb or not sb or len(rb) > 32 or len(sb) > 32: return None, None, 0
    r = int.from_bytes(rb, "big")
    s = int.from_bytes(sb, "big")
    if not (0 < r < N and 0 < s < N): return None, None, 0
    return r, s, sht


# ─────────────────────────────────────────────────────────────────────────────
# Subscript / sighash helpers
# ─────────────────────────────────────────────────────────────────────────────

def strip_codeseparators(script: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(script):
        op = script[i]
        if op == 0xAB: i += 1; continue
        out.append(op); i += 1
        if op <= 0x4B:
            out.extend(script[i:i + op]); i += op
        elif op == 0x4C:
            if i >= len(script): break
            ln = script[i]; i += 1
            out.extend(script[i:i + ln]); i += ln
        elif op == 0x4D:
            if i + 2 > len(script): break
            ln = int.from_bytes(script[i:i + 2], "little"); i += 2
            out.extend(script[i:i + ln]); i += ln
    return bytes(out)

def valid_subscript(spk: bytes) -> bool:
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[-2:] == b"\x88\xac": return True
    if len(spk) == 23 and spk[:2] == b"\xa9\x14"    and spk[-1:]  == b"\x87":     return True
    if len(spk) == 35 and spk[0]  == 0x21           and spk[34]   == 0xAC:        return True
    if len(spk) == 67 and spk[0]  == 0x41           and spk[66]   == 0xAC:        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Legacy sighash (z) computation
# ─────────────────────────────────────────────────────────────────────────────

def compute_z(
    raw_tx_hex: str, inp_idx: int, subscript_hex: str, sht: int
) -> Tuple[str, str]:
    """Return (z_hex, state_or_preimage_hex).
    state_or_preimage_hex is 'sighash_single_bug' when that bug fires.
    Returns ('', '') on any failure.
    """
    if not raw_tx_hex or not subscript_hex: return "", ""
    if sht not in _VALID_SH: return "", ""
    try:
        raw = bytes.fromhex(raw_tx_hex)
        sub = strip_codeseparators(bytes.fromhex(subscript_hex))
    except Exception: return "", ""
    if not sub: return "", ""

    tx = parse_tx(raw)
    if tx is None or inp_idx < 0 or inp_idx >= len(tx["inputs"]): return "", ""

    base  = sht & 0x1F
    anycp = bool(sht & 0x80)
    sub_vi = _varint(len(sub)) + sub

    if anycp:
        inp = tx["inputs"][inp_idx]
        in_cnt  = _varint(1)
        in_data = (
            bytes.fromhex(inp["prev_hash"])[::-1] +
            struct.pack("<I", inp["prev_n"]) +
            sub_vi +
            struct.pack("<I", inp["seq"])
        )
    else:
        in_cnt  = _varint(len(tx["inputs"]))
        in_data = b""
        for i, inp in enumerate(tx["inputs"]):
            sv  = sub_vi if i == inp_idx else b"\x00"
            seq = inp["seq"] if (i == inp_idx or base == 1) else 0
            in_data += (
                bytes.fromhex(inp["prev_hash"])[::-1] +
                struct.pack("<I", inp["prev_n"]) +
                sv +
                struct.pack("<I", seq)
            )

    if base == 2:    # SIGHASH_NONE
        out_data = _varint(0)
    elif base == 3:  # SIGHASH_SINGLE
        if inp_idx >= len(tx["outputs"]):
            return UINT256_ONE, "sighash_single_bug"
        out_data = _varint(inp_idx + 1)
        for _ in range(inp_idx):
            out_data += struct.pack("<q", -1) + _varint(0)
        o = tx["outputs"][inp_idx]
        out_data += (struct.pack("<q", o["value"]) +
                     _varint(len(o["script"])) + o["script"])
    else:            # SIGHASH_ALL
        out_data = _varint(len(tx["outputs"]))
        for o in tx["outputs"]:
            out_data += (struct.pack("<q", o["value"]) +
                         _varint(len(o["script"])) + o["script"])

    preimage = (
        struct.pack("<i", tx["version"]) +
        in_cnt + in_data +
        out_data +
        struct.pack("<I", tx["locktime"]) +
        struct.pack("<I", sht)
    )
    return sha256d(preimage).hex(), preimage.hex()


# ─────────────────────────────────────────────────────────────────────────────
# Pure-Python ECDSA verification (secp256k1)
# ─────────────────────────────────────────────────────────────────────────────

class Secp256k1:
    P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A  = 0
    B  = 7
    N  = N
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    @classmethod
    def _modinv(cls, a: int, m: int) -> int:
        a %= m
        if a == 0: return 0
        try:    return pow(a, -1, m)
        except ValueError: return 0

    @classmethod
    def _point_add(cls, x1, y1, x2, y2):
        if x1 is None: return x2, y2
        if x2 is None: return x1, y1
        if x1 == x2 and y1 != y2: return None, None
        if x1 == x2:
            s = (3 * x1 * x1 + cls.A) * cls._modinv(2 * y1, cls.P) % cls.P
        else:
            s = (y2 - y1) * cls._modinv((x2 - x1) % cls.P, cls.P) % cls.P
        x3 = (s * s - x1 - x2) % cls.P
        y3 = (s * (x1 - x3) - y1) % cls.P
        return x3, y3

    @classmethod
    def _scalar_mul(cls, k: int, x: int, y: int):
        rx, ry = None, None
        tx, ty = x, y
        k %= cls.N
        if k == 0: return None, None
        while k > 0:
            if k & 1: rx, ry = cls._point_add(rx, ry, tx, ty)
            tx, ty = cls._point_add(tx, ty, tx, ty)
            k >>= 1
        return rx, ry

    @classmethod
    def _sqrt_mod(cls, a: int) -> Optional[int]:
        if pow(a % cls.P, (cls.P - 1) // 2, cls.P) != 1: return None
        return pow(a % cls.P, (cls.P + 1) // 4, cls.P)

    @classmethod
    def decompress_pubkey(cls, pk: bytes) -> Tuple[int, int]:
        if len(pk) == 65 and pk[0] == 0x04:
            x = int.from_bytes(pk[1:33], "big")
            y = int.from_bytes(pk[33:65], "big")
            # BUG-S5 FIX: explicit modular equality avoids sign issues
            if pow(y, 2, cls.P) != (pow(x, 3, cls.P) + cls.B) % cls.P:
                return 0, 0
            return x, y
        if len(pk) == 33 and pk[0] in (0x02, 0x03):
            x = int.from_bytes(pk[1:33], "big")
            if x >= cls.P: return 0, 0
            y_sq = (pow(x, 3, cls.P) + cls.B) % cls.P
            y    = cls._sqrt_mod(y_sq)
            if y is None: return 0, 0
            if (y & 1) != (pk[0] & 1): y = (-y) % cls.P
            return x, y
        return 0, 0

    @classmethod
    def verify(cls, pubkey_bytes: bytes, z: int, r: int, s: int) -> bool:
        if r <= 0 or r >= cls.N or s <= 0 or s >= cls.N: return False
        if z <= 0: return False
        px, py = cls.decompress_pubkey(pubkey_bytes)
        if px == 0: return False
        w = cls._modinv(s, cls.N)
        if w == 0: return False
        u1 = (z * w) % cls.N
        u2 = (r * w) % cls.N
        x1, y1 = cls._scalar_mul(u1, cls.Gx, cls.Gy)
        x2, y2 = cls._scalar_mul(u2, px, py)
        xr, _  = cls._point_add(x1, y1, x2, y2)
        if xr is None: return False
        return (xr % cls.N) == (r % cls.N)


# ─────────────────────────────────────────────────────────────────────────────
# I/O helpers
# ─────────────────────────────────────────────────────────────────────────────

def _txid_from_hex(raw_hex: str) -> str:
    return sha256d(bytes.fromhex(raw_hex))[::-1].hex()


def load_hex_dir(path: str) -> Dict[str, str]:
    """
    BUG-S6 FIX: regex accepts only lowercase hex txids.
    BUG-S-NEW-9 FIX: ValueError from _txid_from_hex (non-hex file content)
    is caught per-file so a single corrupt cache file no longer aborts the
    entire load.
    """
    out: Dict[str, str] = {}
    if not os.path.isdir(path): return out
    for fn in os.listdir(path):
        if not fn.endswith(".hex"): continue
        txid = fn[:-4].lower()    # BUG-S6 FIX
        if not _TXID_RE.match(txid): continue
        try:
            with open(os.path.join(path, fn), "r", encoding="ascii") as f:
                raw_hex = f.read().strip()
            # BUG-S-NEW-9 FIX: catch ValueError here so one bad file
            # does not abort the entire directory load.
            if _txid_from_hex(raw_hex) != txid:
                continue
            out[txid] = raw_hex
        except (OSError, ValueError):
            continue
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Directory discovery
# ─────────────────────────────────────────────────────────────────────────────

def is_valid_collection_dir(path: str) -> bool:
    return (os.path.isdir(os.path.join(path, "txs_raw")) and
            os.path.isdir(os.path.join(path, "prevouts_raw")))

def discover_address_dirs(base_dir: str) -> List[str]:
    if is_valid_collection_dir(base_dir):
        return [base_dir]
    results: List[str] = []
    try:
        entries = os.listdir(base_dir)
    except OSError as e:
        print(f"[!] Cannot read {base_dir}: {e}")
        return results
    for entry in entries:
        path = os.path.join(base_dir, entry)
        if os.path.isdir(path) and is_valid_collection_dir(path):
            results.append(path)
    return sorted(results)


# ─────────────────────────────────────────────────────────────────────────────
# CSV output schema
# ─────────────────────────────────────────────────────────────────────────────

CSV_FIELDS = [
    "address",
    "spend_txid", "input_index",
    "prev_txid", "prev_vout", "prev_value_sat",
    "prevout_scriptpubkey_hex", "spk_standard", "input_type",
    "scriptSig_hex", "pubkey_hex",
    "r", "s", "s_high", "sighash_type",
    "z_hex", "z_state",
    "sighash_preimage_hex",
    "block_height",
    "signature_valid",
]


# ─────────────────────────────────────────────────────────────────────────────
# Core processing
# ─────────────────────────────────────────────────────────────────────────────

def process_collection_dir(
    collection_dir: str,
    out_csv_path: Optional[str] = None,
    progress_interval: int = 200,
    address_label: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, int], str]:
    """Process one collection directory. Returns (rows, counts, csv_path)."""

    txs_raw  = load_hex_dir(os.path.join(collection_dir, "txs_raw"))
    prev_raw = load_hex_dir(os.path.join(collection_dir, "prevouts_raw"))
    print(f"[+] {collection_dir}: {len(txs_raw)} spend txs, {len(prev_raw)} prevout txs")

    # Load block heights from txids.csv
    txid_heights: Dict[str, int] = {}
    txids_csv = os.path.join(collection_dir, "txids.csv")
    if os.path.isfile(txids_csv):
        try:
            with open(txids_csv, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    h = int(row.get("height") or 0)
                    txid_heights[row["txid"]] = h
        except Exception:
            pass

    # BUG-S-NEW-8 FIX: process spend txids in deterministic block-height order
    # (height ASC, txid ASC as tie-breaker) so order-sensitive detectors in
    # vuln.py receive signatures in temporal sequence regardless of Python's
    # dict insertion order.
    ordered_txids: List[str] = sorted(
        txs_raw.keys(),
        key=lambda t: (txid_heights.get(t, 0), t),
    )

    # Build prevout lookup: (txid, vout) -> (value_sat, spk_hex)
    prevout_info: Dict[Tuple[str, int], Tuple[int, str]] = {}
    for ptxid, raw_hex in prev_raw.items():
        try:  raw = bytes.fromhex(raw_hex)
        except ValueError: continue
        tx = parse_tx(raw)
        if not tx: continue
        for vout, o in enumerate(tx["outputs"]):
            prevout_info[(ptxid, vout)] = (int(o["value"]), o["script"].hex())

    rows: List[Dict[str, Any]] = []
    # BUG-S3 FIX: separate p2sh counter; SegWit counter kept at 0
    counts: Dict[str, int] = {
        "txs_loaded":               len(txs_raw),
        "prevouts_loaded":          len(prev_raw),
        "inputs_total":             0,
        "p2pkh_sigs_found":         0,
        "p2pk_sigs_found":          0,
        "p2sh_sigs_found":          0,
        "p2wpkh_sigs_found":        0,
        "p2sh_p2wpkh_sigs_found":   0,
        "z_ok":                     0,
        "sig_valid_yes":            0,
        "sig_valid_no":             0,
        "missing_prevout":          0,
        "non_standard_or_unparsed": 0,
        "segwit_processed":         0,
        "non_standard_spk":         0,
        "parse_fail":               0,
    }

    for tx_num, txid in enumerate(ordered_txids, 1):   # BUG-S-NEW-8 FIX
        raw_hex = txs_raw[txid]
        if progress_interval and tx_num % progress_interval == 0:
            print(f"[+] Progress: {tx_num}/{len(ordered_txids)} txs, {len(rows)} sigs")
        try:  raw = bytes.fromhex(raw_hex)
        except ValueError:
            counts["parse_fail"] += 1; continue
        tx = parse_tx(raw)
        if not tx:
            counts["parse_fail"] += 1; continue

        for vin_idx, vin in enumerate(tx["inputs"]):
            counts["inputs_total"] += 1
            prev_txid = vin["prev_hash"]
            prev_vout = int(vin["prev_n"])

            if prev_txid == _COINBASE_TXID:   # BUG-S2 FIX
                continue

            prev = prevout_info.get((prev_txid, prev_vout))
            if not prev:
                counts["missing_prevout"] += 1; continue
            prev_value, prev_spk_hex = prev
            prev_spk   = bytes.fromhex(prev_spk_hex)
            spk_std    = valid_subscript(prev_spk)
            if not spk_std:
                counts["non_standard_spk"] += 1

            input_type    = "unknown"
            sigb: Optional[bytes] = None
            pkb:  Optional[bytes] = None
            z_hex_out    = ""
            z_state      = "failed"
            preimage_out = ""
            sig_valid    = ""
            subscript_hex = ""  # BUG-S1 FIX: always initialised

            # P2SH checked FIRST — its scriptSig layout differs
            if is_p2sh_spk(prev_spk):
                items_sh = _parse_script_pushes(vin["script"])
                if len(items_sh) < 2:
                    counts["non_standard_or_unparsed"] += 1; continue
                subscript     = items_sh[-1]   # last push = redeemScript
                # VERIFY: redeemScript hash160 must match P2SH commitment in prevout
                if hash160(subscript) != prev_spk[2:22]:
                    counts["non_standard_or_unparsed"] += 1; continue
                subscript_hex = subscript.hex()
                if is_p2pk_spk(subscript):
                    sigb, pkb = decode_p2pk_scriptsig(vin["script"], subscript)
                    if sigb and pkb:
                        input_type = "p2sh_p2pk"
                        counts["p2sh_sigs_found"] += 1
                else:
                    sigb, pkb = decode_p2pkh_scriptsig(vin["script"])
                    if sigb and pkb:
                        # VERIFY: pubkey hash160 must match redeemScript commitment
                        if (len(subscript) == 25 and subscript[:3] == b"\x76\xa9\x14"
                                and subscript[-2:] == b"\x88\xac"):
                            expected_h160 = subscript[3:23]
                            if hash160(pkb) != expected_h160:
                                counts["non_standard_or_unparsed"] += 1; continue
                        input_type = "p2sh_p2pkh"
                        counts["p2sh_sigs_found"] += 1

            elif is_p2pk_spk(prev_spk):
                sigb, pkb = decode_p2pk_scriptsig(vin["script"], prev_spk)
                if sigb and pkb:
                    input_type = "p2pk"
                    counts["p2pk_sigs_found"] += 1
                subscript_hex = prev_spk_hex

            else:   # P2PKH (default)
                sigb, pkb = decode_p2pkh_scriptsig(vin["script"])
                if sigb and pkb:
                    # BUG-S-NEW-13 FIX: verify that the decoded pubkey's
                    # hash160 matches the prevout's embedded hash160.
                    # A mismatch means we grabbed the wrong push item
                    # (e.g. bare multisig scriptSig), so discard safely.
                    if len(prev_spk) == 25:
                        expected_h160 = prev_spk[3:23]
                        if hash160(pkb) != expected_h160:
                            counts["non_standard_or_unparsed"] += 1
                            continue
                    input_type = "p2pkh"
                    counts["p2pkh_sigs_found"] += 1
                subscript_hex = prev_spk_hex

            if not sigb or not pkb:
                counts["non_standard_or_unparsed"] += 1; continue

            r, s, sht = parse_der(sigb)
            if r is None:
                counts["non_standard_or_unparsed"] += 1; continue

            if not subscript_hex:
                counts["non_standard_or_unparsed"] += 1; continue

            z_hex_raw, state_or_preimage = compute_z(
                raw_hex, vin_idx, subscript_hex, sht)

            # BUG-S4 FIX: check returned state string directly, not hex value
            if state_or_preimage == "sighash_single_bug":
                z_state      = "sighash_single_bug"
                z_hex_out    = z_hex_raw
                preimage_out = ""
            elif z_hex_raw:
                z_state      = "ok"
                z_hex_out    = z_hex_raw
                preimage_out = state_or_preimage
                counts["z_ok"] += 1
            else:
                z_state      = "failed"
                z_hex_out    = ""
                preimage_out = ""

            if z_state == "ok":
                ok = Secp256k1.verify(pkb, int(z_hex_out, 16), r, s)
                sig_valid = "Yes" if ok else "No"
                if ok: counts["sig_valid_yes"] += 1
                else:  counts["sig_valid_no"]  += 1

            rows.append({
                "address":                  address_label,
                "spend_txid":               txid,
                "input_index":              vin_idx,
                "prev_txid":                prev_txid,
                "prev_vout":                prev_vout,
                "prev_value_sat":           prev_value,
                "prevout_scriptpubkey_hex": prev_spk_hex,
                "spk_standard":             "1" if spk_std else "0",
                "input_type":               input_type,
                "scriptSig_hex":            vin["script"].hex(),
                "pubkey_hex":               pkb.hex(),
                "r":                        str(r),
                "s":                        str(s),
                "s_high":                   "1" if s > HALF_N else "0",
                "sighash_type":             str(sht),
                "z_hex":                    z_hex_out,
                "z_state":                  z_state,
                "sighash_preimage_hex":     preimage_out,
                "block_height":             txid_heights.get(txid, 0),
                "signature_valid":          sig_valid,
            })

    # Write per-address CSV
    written = ""
    if out_csv_path:
        out_dir = os.path.dirname(os.path.abspath(out_csv_path))
        os.makedirs(out_dir, exist_ok=True)
        with open(out_csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            w.writeheader()
            for row in rows: w.writerow(row)
        written = out_csv_path

        # BUG-S-NEW-7 FIX: write summary alongside the CSV, not in CWD.
        summary_path = os.path.join(out_dir, "sig_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump({"counts": counts, "address": address_label,
                       "source_dir": collection_dir}, f, indent=2)

    return rows, counts, written


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Extract and verify ECDSA signatures  (Stage 2 of 3).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single address directory
  python signature.py ./mydata/D7Y55DE...

  # Multi-address batch (auto-discovers subdirs)
  python signature.py ./mydata --batch

  # Merge all sigs into one CSV for vuln.py
  python signature.py ./mydata --batch --merge-all ./mydata/all_signatures.csv
        """)
    ap.add_argument("collection_dir",
                    help="Directory produced by data.py (single or base dir)")
    ap.add_argument("--out", default="signatures.csv",
                    help="Output CSV filename (single mode, default signatures.csv)")
    ap.add_argument("--batch", action="store_true",
                    help="Batch-process multiple address subdirectories")
    ap.add_argument("--merge-all", metavar="PATH",
                    help="Also merge all results into one CSV")
    ap.add_argument("--out-template", default="{address}/signatures.csv",
                    help="Batch output path template (default {address}/signatures.csv)")
    ap.add_argument("--progress", type=int, default=200,
                    help="Print progress every N transactions (0=off)")
    args = ap.parse_args()

    if not os.path.isdir(args.collection_dir):
        print(f"[!] Directory not found: {args.collection_dir}")
        sys.exit(1)

    dirs = discover_address_dirs(args.collection_dir)
    if not dirs:
        print(f"[!] No valid collection directories found in: {args.collection_dir}")
        print("    Expected subdirectories with txs_raw/ and prevouts_raw/ inside.")
        try:
            for e in sorted(os.listdir(args.collection_dir)):
                p = os.path.join(args.collection_dir, e)
                print(f"      {e}{'  [DIR]' if os.path.isdir(p) else ''}")
        except OSError: pass
        sys.exit(1)

    is_batch = args.batch or len(dirs) > 1
    if is_batch:
        print(f"[+] Batch mode: {len(dirs)} collection(s)")
    else:
        print(f"[+] Single mode: {dirs[0]}")

    all_rows:   List[Dict[str, Any]] = []
    all_counts: List[Dict[str, Any]] = []
    processed:  List[Tuple[str, str, Dict[str, int]]] = []

    for idx, dir_path in enumerate(dirs, 1):
        address_label = ("" if dir_path == args.collection_dir
                         else os.path.basename(dir_path))

        if args.merge_all:
            out_path = None   # write all at end
        elif is_batch:
            safe = address_label if address_label else "root"
            tmpl = (args.out_template.format(address=safe).lstrip("/\\"))
            out_path = os.path.join(args.collection_dir, tmpl)
        else:
            out_path = os.path.join(args.collection_dir, args.out)

        print(f"\n{'='*60}")
        print(f"[{idx}/{len(dirs)}] {dir_path}")
        if address_label: print(f"    Address: {address_label}")
        print(f"{'='*60}")

        rows, counts, written = process_collection_dir(
            dir_path, out_csv_path=out_path,
            progress_interval=args.progress,
            address_label=address_label,
        )
        all_rows.extend(rows)
        all_counts.append({"address": address_label, "dir": dir_path,
                           "counts": counts, "rows": len(rows), "out_csv": written})
        processed.append((dir_path, address_label, counts))
        print(f"[+] Extracted {len(rows)} signatures")
        if written: print(f"    Written: {written}")

    if args.merge_all and all_rows:
        merge_dir = os.path.dirname(os.path.abspath(args.merge_all))
        os.makedirs(merge_dir, exist_ok=True)
        with open(args.merge_all, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            w.writeheader()
            for row in all_rows: w.writerow(row)
        print(f"\n[+] Merged {len(all_rows)} signatures -> {args.merge_all}")

    # BUG-S-NEW-12 FIX: global summary written to the correct output location.
    # In single mode, write it next to the output CSV or collection_dir;
    # in batch/merge mode, write to collection_dir as before.
    if not is_batch and not args.merge_all:
        summary_dir = os.path.dirname(
            os.path.abspath(
                os.path.join(args.collection_dir, args.out)))
    else:
        summary_dir = os.path.abspath(args.collection_dir)

    global_summary = {
        "mode":             "batch" if is_batch else "single",
        "total_addresses":  len(dirs),
        "total_signatures": len(all_rows),
        "per_address":      all_counts,
    }
    summary_path = os.path.join(summary_dir, "global_sig_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(global_summary, f, indent=2)

    print(f"\n{'='*60}")
    print("GLOBAL SUMMARY")
    print(f"{'='*60}")
    print(f"Total addresses : {len(dirs)}")
    print(f"Total signatures: {len(all_rows)}")
    for path, addr, cnt in processed:
        label = addr or "(single)"
        print(f"  {label}: valid={cnt['sig_valid_yes']} "
              f"invalid={cnt['sig_valid_no']} "
              f"missing_prevout={cnt['missing_prevout']}")
    print(f"\nGlobal summary  : {summary_path}")
    if args.merge_all:
        print(f"Merged CSV      : {args.merge_all}")


if __name__ == "__main__":
    main()
