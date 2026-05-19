#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
import sys

from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Set

try:
    from signature import Secp256k1
except Exception as _ie:
    Secp256k1 = None  # type: ignore
    logging.getLogger(__name__).warning(
        "Could not import Secp256k1 from signature.py: %s  "
        "Key-recovery verification disabled.", _ie)

# ── secp256k1 constants ───────────────────────────────────────────────────────
N      = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
N_BITS = N.bit_length()
P      = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
HALF_N = N >> 1
_256BIT_MASK = (1 << 256) - 1   # BUG-V-NEW-15: clamp guard

# ── Detection thresholds ──────────────────────────────────────────────────────
SMALL_K_BITS  = 128
MIN_WEAK_RNG  = 10
MIN_BIASED    = 20
MIN_CORR      = 8
MIN_HNP       = 10
MIN_PART_LEAK = 10
MIN_DET_K     = 5
MIN_POLY      = 8    # BUG-V-NEW-21 FIX: raised from 5 to 8
MIN_LCG       = 10   # BUG-V-NEW-22 FIX: raised from 6 to 10

ENTROPY_THRESH = 6.5
ENTROPY_WARN   = 7.0
CORR_THRESH    = 0.90
BIAS_RATIO_LO  = 0.05
BIAS_RATIO_HI  = 0.95
CHI_SQ_PVAL    = 0.01

# ── Severity table ────────────────────────────────────────────────────────────
VULN_SEVERITY: Dict[str, int] = {
    "nonce_reuse":                   100,
    "cross_key_nonce_reuse":          95,
    "small_k":                        90,
    "polynomial_nonce":               88,
    "lcg_nonce_pattern":              87,
    "weak_rng":                       85,
    "strong_partial_nonce_leak":      82,
    "strong_hnp_partial_leak":        80,
    "duplicate_r":                    78,
    "deterministic_k_bug":            75,
    "biased_nonce":                   70,
    "nonce_correlation":              65,
    "transaction_malleability":       60,
    "hnp_lattice_score":              60,
    "timing_side_channel_indicator":  55,
    "entropy_deficiency":             50,
    "bit_balance_anomaly":            45,
    "sighash_reuse_pattern":          40,
}

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SecurityScore:
    pubkey_hex: str
    total_score: int = 100
    vulnerability_scores: Dict[str, int] = field(default_factory=dict)
    risk_level: str = "low"
    recommendations: List[str] = field(default_factory=list)

    def calculate_risk_level(self) -> None:
        if   self.total_score <= 30: self.risk_level = "critical"
        elif self.total_score <= 50: self.risk_level = "high"
        elif self.total_score <= 70: self.risk_level = "medium"
        elif self.total_score <= 85: self.risk_level = "low"
        else:                        self.risk_level = "minimal"


@dataclass
class Sig:
    spend_txid:   str
    input_index:  int
    pubkey_hex:   str
    r:            int
    s:            int
    z:            int
    sighash_type: int  = 1
    s_high:       bool = False
    z_state:      str  = "ok"
    block_height: int  = 0


@dataclass
class Finding:
    pubkey_hex: str
    vuln:       str
    severity:   int
    confidence: float
    evidence:   Dict[str, Any]
    mitigation: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Math helpers
# ─────────────────────────────────────────────────────────────────────────────

def modinv(a: int, m: int) -> int:
    a %= m
    if a == 0: return 0
    try:    return pow(a, -1, m)
    except ValueError: return 0

def _popcount(n: int) -> int:
    return bin(n).count("1")

def _safe_to_32bytes(v: int) -> bytes:
    """
    BUG-V-NEW-15 FIX: clamp values that exceed 256 bits before calling
    to_bytes(32).  Valid secp256k1 scalars are always < N < 2^256, but
    corrupt CSV rows could supply larger integers that cause OverflowError.
    """
    return (v & _256BIT_MASK).to_bytes(32, "big")

def shannon_entropy(vals_256bit: List[int]) -> float:
    if not vals_256bit: return 0.0
    all_bytes: List[int] = []
    for v in vals_256bit:
        all_bytes.extend(_safe_to_32bytes(v))  # BUG-V-NEW-15 FIX
    counts = Counter(all_bytes)
    total  = len(all_bytes)
    return -sum((c/total)*math.log2(c/total) for c in counts.values() if c)

def byte_position_entropy(vals: List[int]) -> Dict[str, float]:
    if not vals: return {"min": 0.0, "max": 0.0, "avg": 0.0, "theoretical_max": 8.0}
    entropies: List[float] = []
    for pos in range(32):
        bv = [(_safe_to_32bytes(v)[pos]) for v in vals]  # BUG-V-NEW-15 FIX
        freq  = Counter(bv); total = len(bv)
        ent   = -sum((c/total)*math.log2(c/total) for c in freq.values() if c)
        entropies.append(ent)
    return {"min": min(entropies), "max": max(entropies),
            "avg": sum(entropies)/len(entropies), "theoretical_max": 8.0}

def _bit_balance(vals_256bit: List[int]) -> float:
    if not vals_256bit: return 0.5
    ones = sum(_popcount(v & _256BIT_MASK) for v in vals_256bit)  # BUG-V-NEW-15 FIX
    return ones / (len(vals_256bit) * 256)

def _msb_run_test(r_vals: List[int]) -> Dict[str, Any]:
    if not r_vals: return {"max_run": 0, "runs": []}
    msbs = [(r >> 248) & 0xFF for r in r_vals]
    runs = []; current = msbs[0]; run_len = 1
    for m in msbs[1:]:
        if m == current: run_len += 1
        else: runs.append(run_len); current = m; run_len = 1
    runs.append(run_len)
    return {"max_run": max(runs), "runs": runs}

def pearson_correlation(x: List[float], y: List[float]) -> float:
    n = len(x)
    if n < 2: return 0.0
    mx = sum(x)/n; my = sum(y)/n
    num = sum((xi-mx)*(yi-my) for xi, yi in zip(x, y))
    dx  = sum((xi-mx)**2 for xi in x)
    dy  = sum((yi-my)**2 for yi in y)
    if dx <= 0 or dy <= 0: return 0.0
    return num / math.sqrt(dx*dy)

def _normal_sf(z: float) -> float:
    if z < -8: return 1.0
    if z >  8: return 0.0
    return 0.5 * math.erfc(z / math.sqrt(2))

def chi_square_uniformity(vals: List[int], n_bins: int = 256) -> Tuple[float, float]:
    if len(vals) < n_bins: return 0.0, 1.0
    observed = Counter((v >> 248) & 0xFF for v in vals)
    total    = len(vals); expected = total / n_bins
    chi2     = sum((observed.get(i,0)-expected)**2/expected for i in range(n_bins))
    df       = n_bins - 1
    z        = (chi2/df)**(1/3)
    mu       = 1 - 2/(9*df)
    sigma    = math.sqrt(2/(9*df))
    p_approx = _normal_sf((z-mu)/sigma) if sigma > 0 else 0.0
    return chi2, p_approx


# ─────────────────────────────────────────────────────────────────────────────
# CSV loader
# ─────────────────────────────────────────────────────────────────────────────

def load_sigs(path: str) -> Tuple[List[Sig], Dict[str, int]]:
    """
    BUG-V-NEW-13 FIX: open with errors='replace' so Windows-1252 or other
    non-UTF-8 bytes do not crash the loader.  A warning is emitted when any
    bytes are substituted.
    """
    valid_sigs: List[Sig] = []
    stats = {
        "total_rows": 0, "valid_sigs": 0, "invalid_sigs": 0,
        "invalid_r": 0, "invalid_s": 0, "invalid_z": 0,
        "high_s": 0, "sighash_bug_skipped": 0,
        "missing_fields": 0,   # BUG-V5 FIX: counted directly
        "parse_errors": 0,
        "unicode_replacements": 0,   # BUG-V-NEW-13 FIX
    }

    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        # Detect unicode replacement characters in the raw read
        raw_content = f.read()
        if "\ufffd" in raw_content:
            stats["unicode_replacements"] = raw_content.count("\ufffd")
            logger.warning(
                "load_sigs: %d non-UTF-8 byte(s) replaced in %s. "
                "Some rows may be malformed.",
                stats["unicode_replacements"], path)
        import io
        rd = csv.DictReader(io.StringIO(raw_content))
        for row in rd:
            stats["total_rows"] += 1
            try:
                if row.get("signature_valid","") != "Yes":
                    stats["invalid_sigs"] += 1; continue

                r_str = row.get("r","").strip().strip('"').strip("'")
                s_str = row.get("s","").strip().strip('"').strip("'")
                if not r_str or not s_str:
                    stats["missing_fields"] += 1; continue  # BUG-V5 FIX

                r_val = int(r_str); s_val = int(s_str)
                z_hex = row.get("z_hex","").strip()
                if z_hex.startswith(("0x","0X")): z_hex = z_hex[2:]
                z_val   = int(z_hex, 16) if z_hex else 0
                z_state = row.get("z_state","ok").strip()
                sht     = int(row.get("sighash_type","1") or "1")
                bh      = int(row.get("block_height","0") or "0")

                if r_val <= 0 or r_val >= N: stats["invalid_r"] += 1; continue
                if s_val <= 0 or s_val >= N: stats["invalid_s"] += 1; continue
                if z_state == "sighash_single_bug":
                    stats["sighash_bug_skipped"] += 1; continue
                if z_val <= 0: stats["invalid_z"] += 1; continue

                s_high = s_val > HALF_N
                if s_high: stats["high_s"] += 1

                valid_sigs.append(Sig(
                    spend_txid   = row.get("spend_txid",""),
                    input_index  = int(row.get("input_index","0") or "0"),
                    pubkey_hex   = row.get("pubkey_hex",""),
                    r=r_val, s=s_val, z=z_val,
                    sighash_type = sht, s_high=s_high,
                    z_state=z_state, block_height=bh,
                ))
                stats["valid_sigs"] += 1
            except (ValueError, KeyError) as exc:
                stats["parse_errors"] += 1
                logger.debug("Parse error row %d: %s", stats["total_rows"], exc)
    return valid_sigs, stats


# ─────────────────────────────────────────────────────────────────────────────
# Private key recovery
# ─────────────────────────────────────────────────────────────────────────────

def recover_priv_from_nonce_reuse(
    r: int, s1: int, z1: int, s2: int, z2: int, pubkey_hex: str = ""
) -> Tuple[Optional[int], Optional[int], Dict[str, Any]]:
    diag: Dict[str, Any] = {"verified": False, "method": "nonce_reuse"}
    if z1 == z2:
        diag["error"] = "Identical z — cannot distinguish from same-message signing"
        return None, None, diag
    ds = (s1-s2) % N
    if ds == 0:
        diag["error"] = "s1==s2 but z1!=z2 — not standard nonce reuse"
        return None, None, diag
    dsi = modinv(ds, N)
    if dsi == 0:
        diag["error"] = "No modinv for (s1-s2)"; return None, None, diag
    k  = ((z1-z2)*dsi) % N
    if k == 0:
        diag["error"] = "Recovered zero nonce"; return None, None, diag
    ri = modinv(r, N)
    if ri == 0:
        diag["error"] = "No modinv for r"; return None, None, diag
    d = ((s1*k - z1)*ri) % N
    if d == 0:
        diag["error"] = "Recovered zero private key"; return None, None, diag

    if pubkey_hex and Secp256k1 is not None:
        try:
            pk_bytes = bytes.fromhex(pubkey_hex)
            gx, gy   = Secp256k1.decompress_pubkey(pk_bytes)
            if gx != 0:
                for d_cand in (d, N-d):
                    qx, qy = Secp256k1._scalar_mul(d_cand, Secp256k1.Gx, Secp256k1.Gy)
                    if qx == gx and qy == gy:
                        d = d_cand; diag["verified"] = True; break
        except Exception as exc:
            diag["verify_error"] = str(exc)

    return d, k, diag


# ─────────────────────────────────────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────────────────────────────────────

def detect_duplicate_r_and_nonce_reuse(
    by_pk: Dict[str, List[Sig]]
) -> Tuple[List[Finding], Dict[int, Set[str]]]:
    MAX_PAIRS = 50
    findings: List[Finding] = []
    global_r_to_pks: Dict[int, Set[str]] = defaultdict(set)

    for pk, sigs in by_pk.items():
        rmap: Dict[int, List[Sig]] = defaultdict(list)
        for sig in sigs:
            rmap[sig.r].append(sig)
            global_r_to_pks[sig.r].add(pk)

        for r_val, grp in rmap.items():
            if len(grp) < 2: continue
            confidence = min(1.0, 0.7 + (len(grp)-2)*0.05)
            findings.append(Finding(
                pubkey_hex = pk,
                vuln       = "duplicate_r",
                severity   = VULN_SEVERITY["duplicate_r"],
                confidence = confidence,
                evidence   = {
                    "r_hex":    f"{r_val:064x}",
                    "count":    len(grp),
                    "examples": [f"{g.spend_txid}:{g.input_index}" for g in grp[:4]],
                },
                mitigation = "Use RFC 6979 deterministic nonce generation",
            ))

            recovered: List[Dict[str, Any]] = []
            for i in range(len(grp)):
                # BUG-V-NEW-14 FIX: outer loop guard — skip when already at limit
                if len(recovered) >= MAX_PAIRS: break
                for j in range(i+1, len(grp)):
                    a, b = grp[i], grp[j]
                    if a.s == b.s or not a.z or not b.z: continue
                    d, k, diag = recover_priv_from_nonce_reuse(
                        r_val, a.s, a.z, b.s, b.z, pk)
                    if d is not None:
                        recovered.append({
                            "sig1":               f"{a.spend_txid}:{a.input_index}",
                            "sig2":               f"{b.spend_txid}:{b.input_index}",
                            "recovered_priv_hex": f"{d:064x}",
                            "recovered_k_hex":    f"{k:064x}",
                            "verified":           diag.get("verified", False),
                        })
                        if len(recovered) >= MAX_PAIRS: break

            if recovered:
                verified   = any(p.get("verified") for p in recovered)
                findings.append(Finding(
                    pubkey_hex = pk,
                    vuln       = "nonce_reuse",
                    severity   = VULN_SEVERITY["nonce_reuse"],
                    confidence = 1.0 if verified else 0.95,
                    evidence   = {
                        "r_hex":           f"{r_val:064x}",
                        "recovered_pairs": recovered,
                        "total_pairs":     len(recovered),
                        "max_pairs_checked": MAX_PAIRS,
                        "truncated":       len(recovered) >= MAX_PAIRS,
                    },
                    mitigation = "Immediately rotate funds. Never reuse nonces. Use RFC 6979.",
                ))

    return findings, global_r_to_pks


def detect_cross_key_nonce_reuse(
    global_r_to_pks: Dict[int, Set[str]], by_pk: Dict[str, List[Sig]]
) -> List[Finding]:
    """
    BUG-V-NEW-18 FIX: emits ONE aggregated Finding per shared-r value instead
    of one Finding per affected pubkey.  The original O(K) output per r value
    (K = number of affected pubkeys) became O(K²) total evidence size when
    each Finding listed all K pubkeys.  The aggregated form is O(K) overall.
    """
    findings: List[Finding] = []
    for r_val, pks in global_r_to_pks.items():
        if len(pks) <= 1: continue
        pk_list    = sorted(pks)
        confidence = min(1.0, 0.6 + (len(pks)-2)*0.1)
        cross_sigs = sum(len(by_pk.get(pk,[])) for pk in pks)
        # One finding that covers all affected pubkeys; use the first pk as
        # the primary for scoring (all affected keys get scored in the main loop
        # via phase1_by_pk).
        findings.append(Finding(
            pubkey_hex = pk_list[0],
            vuln       = "cross_key_nonce_reuse",
            severity   = VULN_SEVERITY["cross_key_nonce_reuse"],
            confidence = confidence,
            evidence   = {
                "r_hex":            f"{r_val:064x}",
                "pubkeys_affected":  len(pks),
                "all_pubkeys":       pk_list,          # full list, not just top-5
                "total_cross_sigs":  cross_sigs,
                "note": "Same nonce k used across different private keys.",
            },
            mitigation = "Audit RNG; ensure unique nonces per key per signature",
        ))
    return findings


def detect_transaction_malleability(sigs: List[Sig]) -> Optional[Finding]:
    if not sigs: return None  # BUG-V2 FIX
    high_s = [s for s in sigs if s.s_high]
    if not high_s: return None
    confidence = min(1.0, len(high_s)/5.0)
    return Finding(
        pubkey_hex = high_s[0].pubkey_hex,   # BUG-V2 FIX: use actual high-s sig
        vuln       = "transaction_malleability",
        severity   = VULN_SEVERITY["transaction_malleability"],
        confidence = confidence,
        evidence   = {
            "high_s_count":  len(high_s),
            "total_sigs":    len(sigs),
            "ratio":         round(len(high_s)/len(sigs), 4),
            "example_txids": [s.spend_txid for s in high_s[:3]],
        },
        mitigation = "Use low-S signature generation (enforce s <= N/2 per BIP 62)",
    )


def detect_small_k(sigs: List[Sig]) -> Optional[Dict[str, Any]]:
    hits = [s for s in sigs if 0 < s.r < (1 << SMALL_K_BITS)]
    if not hits: return None
    avg_bits   = sum(s.r.bit_length() for s in hits) / len(hits)
    confidence = max(0.4, min(1.0, (SMALL_K_BITS - avg_bits + 16) / 32))
    return {
        "small_r_count": len(hits), "total_sigs": len(sigs),
        "small_r_bits": SMALL_K_BITS, "avg_r_bits": round(avg_bits, 1),
        "confidence": round(confidence, 4),
        "example_r_hex": f"{hits[0].r:064x}",
        "note": "Small r is a heuristic for small k; r=(k·G).x mod N.",
    }


def detect_biased_nonce(r_vals: List[int]) -> Tuple[bool, Dict[str, Any]]:
    n = len(r_vals)
    if n < MIN_BIASED:
        return False, {"reason": "insufficient_samples", "required": MIN_BIASED, "got": n}
    evidence: Dict[str, Any] = {"tests": {}}
    flags: List[str] = []

    msb_ones  = sum(1 for r in r_vals if r >> 255 == 1)   # BUG-V-NEW-20 FIX
    msb_ratio = msb_ones / n
    evidence["tests"]["msb_ratio"] = round(msb_ratio, 6)
    if msb_ratio < BIAS_RATIO_LO or msb_ratio > BIAS_RATIO_HI:
        flags.append(f"msb_bias:{msb_ratio:.3f}")

    half_ratio = sum(1 for r in r_vals if r > HALF_N) / n
    evidence["tests"]["half_ratio"] = round(half_ratio, 6)
    if half_ratio < BIAS_RATIO_LO or half_ratio > BIAS_RATIO_HI:
        flags.append(f"median_bias:{half_ratio:.3f}")

    mn, mx = min(r_vals), max(r_vals)
    range_ratio = (mx-mn) / N
    evidence["tests"]["range_ratio"] = round(range_ratio, 8)
    if range_ratio < 0.001:  flags.append(f"extremely_clustered:{range_ratio:.8f}")
    elif range_ratio < 0.01: flags.append(f"clustered_values:{range_ratio:.6f}")

    zero_ratio = sum(1 for r in r_vals if r < (1 << (N_BITS-8))) / n
    evidence["tests"]["leading_zero_ratio"] = round(zero_ratio, 6)
    if zero_ratio > 0.15: flags.append(f"leading_zeros:{zero_ratio:.3f}")

    if n >= 256:
        chi2, p_val = chi_square_uniformity(r_vals)
        evidence["tests"]["chi_square_top_byte"] = round(chi2, 2)
        evidence["tests"]["chi_square_p_value"]  = round(p_val, 6)
        if p_val < CHI_SQ_PVAL:
            flags.append(f"chi_square_nonuniform:p={p_val:.4f}")

    evidence["bias_flags"] = flags
    return len(flags) >= 2, evidence


def detect_weak_rng(r_vals: List[int]) -> Tuple[bool, Dict[str, Any]]:
    if len(r_vals) < MIN_WEAK_RNG:
        return False, {"reason": "insufficient_samples",
                       "required": MIN_WEAK_RNG, "got": len(r_vals)}
    evidence: Dict[str, Any] = {}
    flags: List[str] = []
    confidence = 0.0

    byte_entropy = shannon_entropy(r_vals)
    evidence["byte_entropy"] = round(byte_entropy, 4)
    if byte_entropy < ENTROPY_THRESH:
        flags.append("critically_low_entropy"); confidence += 0.5
    elif byte_entropy < ENTROPY_WARN:
        flags.append("low_entropy"); confidence += 0.25

    bit_bal   = _bit_balance(r_vals)
    deviation = abs(bit_bal - 0.5)
    evidence["bit_balance"] = round(bit_bal, 6)
    if deviation > 0.08:
        flags.append("severe_bit_imbalance"); confidence += 0.4
    elif deviation > 0.05:
        flags.append("bit_imbalance"); confidence += 0.2

    pos_ent = byte_position_entropy(r_vals)
    evidence["byte_position_entropy"] = {k: round(v, 4) for k, v in pos_ent.items()}
    if pos_ent["avg"] < 4.0:
        flags.append("very_low_position_entropy"); confidence += 0.3
    elif pos_ent["avg"] < 6.0 and pos_ent["max"] < 7.5:
        flags.append("low_position_entropy"); confidence += 0.15

    prefixes     = [r >> (256-32) for r in r_vals]
    uniq_pref    = len(set(prefixes))
    prefix_ratio = uniq_pref / len(r_vals)
    evidence["unique_prefixes"]        = uniq_pref
    evidence["total_samples"]          = len(r_vals)
    evidence["prefix_diversity_ratio"] = round(prefix_ratio, 4)
    if uniq_pref == 1 and len(r_vals) > 10:
        flags.append("identical_prefixes"); confidence += 0.4
    elif prefix_ratio < 0.1 and len(r_vals) > 20:
        flags.append("low_prefix_diversity"); confidence += 0.2

    msb_runs = _msb_run_test(r_vals)
    evidence["msb_run_test"] = msb_runs
    if msb_runs.get("max_run", 0) > max(5, len(r_vals)//4):
        flags.append("suspicious_msb_runs"); confidence += 0.2

    evidence["flags"]      = flags
    evidence["confidence"] = round(min(confidence, 1.0), 4)
    is_weak = len(flags) >= 2 and confidence >= 0.6  # BUG-V-NEW-23 FIX: raised from 0.5
    return is_weak, evidence


def detect_nonce_correlation(r_vals: List[int]) -> Tuple[bool, Dict[str, Any]]:
    if len(r_vals) < MIN_CORR:
        return False, {"reason": "insufficient_samples",
                       "required": MIN_CORR, "got": len(r_vals)}
    evidence: Dict[str, Any] = {}
    pearson_r = 0.0
    if len(r_vals) >= 3:
        pearson_r = abs(pearson_correlation(r_vals[:-1], r_vals[1:]))
        evidence["pearson_consecutive"] = round(pearson_r, 6)
    pearson_2 = 0.0
    if len(r_vals) >= 4:
        pearson_2 = abs(pearson_correlation(r_vals[:-2], r_vals[2:]))
        evidence["pearson_lag2"] = round(pearson_2, 6)
    max_autocorr = 0.0
    if len(r_vals) >= 20:
        max_lag = max(2, min(6, len(r_vals)//3))
        corrs   = [abs(pearson_correlation(r_vals[:-lag], r_vals[lag:]))
                   for lag in range(1, max_lag) if len(r_vals)-lag >= 5]
        if corrs:
            max_autocorr = max(corrs)
            evidence["autocorrelations"]    = [round(c, 6) for c in corrs]
            evidence["max_autocorrelation"] = round(max_autocorr, 6)
    is_corr = (pearson_r >= CORR_THRESH or
               (pearson_r >= 0.80 and pearson_2 >= 0.80) or
               max_autocorr >= CORR_THRESH)
    return is_corr, evidence


def detect_deterministic_k_bug(
    r_vals: List[int], z_vals: List[int]
) -> Tuple[bool, Dict[str, Any]]:
    if len(r_vals) < MIN_DET_K:
        return False, {"reason": "insufficient_samples"}
    evidence: Dict[str, Any] = {}
    flags: List[str] = []
    r_bytes = [r.to_bytes(32, "big") for r in r_vals]
    for w in (4, 8, 16):
        if len(set(rb[:w] for rb in r_bytes)) == 1:
            flags.append(f"common_prefix_{w}_bytes")
            evidence[f"common_prefix_{w}"] = True
        if len(set(rb[-w:] for rb in r_bytes)) == 1:
            flags.append(f"common_suffix_{w}_bytes")
            evidence[f"common_suffix_{w}"] = True
    collisions = sum(1 for r, z in zip(r_vals, z_vals) if z and (z%N) == r)
    if collisions > 0:
        flags.append("r_equals_z"); evidence["r_z_collisions"] = collisions
    if len(r_vals) >= 3:
        diffs = [(r_vals[i+1]-r_vals[i])%N for i in range(len(r_vals)-1)]
        if len(set(diffs)) <= max(1, len(diffs)//10):
            flags.append("constant_differences"); evidence["constant_differences"] = True
    evidence["flags"] = flags
    return len(flags) > 0, evidence


def detect_polynomial_nonce(
    r_vals: List[int], z_vals: List[int]
) -> Tuple[bool, Dict[str, Any]]:
    if len(r_vals) < MIN_POLY:
        return False, {"reason": "insufficient_samples",
                       "required": MIN_POLY, "got": len(r_vals)}
    evidence: Dict[str, Any] = {}
    flags: List[str] = []

    diffs_1   = [(r_vals[i+1]-r_vals[i])%N for i in range(len(r_vals)-1)]
    unique_d1 = len(set(diffs_1))
    evidence["first_diff_unique"] = unique_d1
    if unique_d1 == 1 and len(r_vals) >= 3:
        flags.append("linear_polynomial")
        evidence["constant_first_diff"] = f"{diffs_1[0]:064x}"
    if len(diffs_1) >= 2:
        diffs_2   = [(diffs_1[i+1]-diffs_1[i])%N for i in range(len(diffs_1)-1)]
        unique_d2 = len(set(diffs_2))
        evidence["second_diff_unique"] = unique_d2
        if unique_d2 == 1 and len(r_vals) >= 4:
            flags.append("quadratic_polynomial")
            evidence["constant_second_diff"] = f"{diffs_2[0]:064x}"
        if len(diffs_2) >= 2:
            diffs_3   = [(diffs_2[i+1]-diffs_2[i])%N for i in range(len(diffs_2)-1)]
            unique_d3 = len(set(diffs_3))
            evidence["third_diff_unique"] = unique_d3
            if unique_d3 == 1 and len(r_vals) >= 5:
                flags.append("cubic_polynomial")
                evidence["constant_third_diff"] = f"{diffs_3[0]:064x}"

    r_eq_z = sum(1 for r, z in zip(r_vals, z_vals) if z and r == (z%N))
    if r_eq_z > 0:
        flags.append("r_equals_z_polynomial"); evidence["r_eq_z_count"] = r_eq_z

    if len(r_vals) >= 3:
        ratios = []
        for i in range(len(r_vals)-1):
            if r_vals[i] != 0:
                ri_inv = modinv(r_vals[i], N)
                if ri_inv: ratios.append((r_vals[i+1]*ri_inv)%N)
        if ratios and len(set(ratios)) == 1:
            flags.append("constant_multiplicative_ratio")
            evidence["constant_ratio"] = f"{ratios[0]:064x}"

    # near-linear detection for noisy polynomial sequences
    near_linear_thresh = max(2, len(r_vals) // 20)
    if (unique_d1 <= near_linear_thresh and len(r_vals) >= MIN_POLY
            and "linear_polynomial" not in flags
            and "low_diff_diversity" not in flags):
        if "r_equals_z_polynomial" in flags or (shannon_entropy(r_vals) < ENTROPY_WARN):
            flags.append("near_linear_polynomial")
            evidence["near_linear_diff_diversity"] = unique_d1
            evidence["near_linear_threshold"] = near_linear_thresh

    evidence["flags"] = flags; evidence["sample_size"] = len(r_vals)
    # Strong flags indicate definite polynomial pattern
    strong_flags = {"linear_polynomial", "quadratic_polynomial", "cubic_polynomial",
                    "constant_multiplicative_ratio"}
    has_strong = bool(strong_flags & set(flags))
    return has_strong or len(flags) >= 2, evidence


def detect_lcg_nonce_pattern(r_vals: List[int]) -> Tuple[bool, Dict[str, Any]]:
    if len(r_vals) < MIN_LCG:
        return False, {"reason": "insufficient_samples",
                       "required": MIN_LCG, "got": len(r_vals)}
    evidence: Dict[str, Any] = {}
    flags: List[str] = []

    diffs = [(r_vals[i+1]-r_vals[i])%N for i in range(len(r_vals)-1)]
    if len(diffs) >= 3:
        diff_ratios = []
        for i in range(len(diffs)-1):
            if diffs[i] != 0:
                di_inv = modinv(diffs[i], N)
                if di_inv: diff_ratios.append((diffs[i+1]*di_inv)%N)
        if diff_ratios:
            uniq = len(set(diff_ratios))
            evidence["diff_ratio_unique"] = uniq
            evidence["diff_ratio_total"]  = len(diff_ratios)
            if uniq == 1:
                flags.append("constant_diff_ratio")
                evidence["lcg_multiplier_candidate"] = f"{diff_ratios[0]:064x}"
            elif uniq <= max(2, len(diff_ratios)//5):
                flags.append("near_constant_diff_ratio")
                evidence["near_constant_ratio_diversity"] = uniq

    seen: Dict[int, int] = {}
    for i, r in enumerate(r_vals):
        if r in seen:
            cand = i - seen[r]
            valid = all(r_vals[j] == r_vals[j+cand]
                        for j in range(seen[r], min(i, len(r_vals)-cand)))
            if valid and cand > 0:
                flags.append("periodic_r_values"); evidence["period"] = cand; break
        seen[r] = i

    for mod_val in (256, 65537, 1_000_003):
        residues = [r%mod_val for r in r_vals]
        if len(residues) >= 4:
            x0, x1, x2 = residues[0], residues[1], residues[2]
            d01 = (x1-x0)%mod_val
            if d01 != 0:
                d01_inv = modinv(d01, mod_val)
                if d01_inv:
                    a_c = ((x2-x1)*d01_inv)%mod_val
                    b_c = (x1-a_c*x0)%mod_val
                    matches = sum(1 for j in range(len(residues)-1)
                                  if (a_c*residues[j]+b_c)%mod_val == residues[j+1])
                    if matches/(len(residues)-1) > 0.90:
                        flags.append(f"lcg_mod_{mod_val}")
                        evidence[f"lcg_mod_{mod_val}"] = {
                            "a": a_c, "b": b_c,
                            "match_ratio": round(matches/(len(residues)-1), 4)}

    if len(r_vals) >= 4:
        r0, r1, r2 = r_vals[0], r_vals[1], r_vals[2]
        d = (r1-r0)%N; e = (r2-r1)%N
        if d != 0:
            d_inv = modinv(d, N)
            if d_inv:
                a_f = (e*d_inv)%N; b_f = (r1-a_f*r0)%N
                matches = sum(1 for j in range(len(r_vals)-1)
                              if (a_f*r_vals[j]+b_f)%N == r_vals[j+1])
                mr = matches/(len(r_vals)-1)
                evidence["lcg_full_n"] = {
                    "a_hex": f"{a_f:064x}", "b_hex": f"{b_f:064x}",
                    "match_ratio": round(mr, 4)}
                if mr > 0.90:
                    flags.append("lcg_full_n_recovered")

    top_bytes  = [r >> 248 for r in r_vals]
    top_unique = len(set(top_bytes))
    evidence["top_byte_unique"] = top_unique; evidence["top_byte_total"] = len(top_bytes)
    if top_unique <= 2 and len(r_vals) >= MIN_LCG:
        flags.append("low_top_byte_diversity")

    evidence["flags"] = flags; evidence["sample_size"] = len(r_vals)
    strong_flags = {"constant_diff_ratio", "lcg_full_n_recovered",
                    "periodic_r_values", "lcg_mod_256", "lcg_mod_65537", "lcg_mod_1000003"}
    has_strong = bool(strong_flags & set(flags))
    return has_strong or len(flags) >= 2, evidence


def detect_entropy_deficiency(r_vals: List[int]) -> Optional[Finding]:
    if len(r_vals) < 10: return None
    ent = shannon_entropy(r_vals)
    if ent >= ENTROPY_WARN: return None
    confidence = 0.6 if ent < ENTROPY_THRESH else 0.4
    return Finding(
        pubkey_hex = "",
        vuln       = "entropy_deficiency",
        severity   = VULN_SEVERITY["entropy_deficiency"],
        confidence = confidence,
        evidence   = {"byte_entropy": round(ent, 4), "threshold": ENTROPY_WARN},
        mitigation = "Replace RNG with CSPRNG (/dev/urandom, getrandom)",
    )


def detect_bit_balance_anomaly(r_vals: List[int]) -> Optional[Finding]:
    if len(r_vals) < 10: return None
    bal = _bit_balance(r_vals)
    dev = abs(bal - 0.5)
    if dev < 0.04: return None
    return Finding(
        pubkey_hex = "",
        vuln       = "bit_balance_anomaly",
        severity   = VULN_SEVERITY["bit_balance_anomaly"],
        confidence = min(1.0, dev*5),
        evidence   = {"bit_balance": round(bal, 6),
                      "deviation_from_0.5": round(dev, 6)},
        mitigation = "Inspect nonce generation for fixed-bit injection or masking bugs",
    )


def detect_sighash_reuse(sigs: List[Sig]) -> Optional[Finding]:
    if not sigs: return None  # BUG-V3 FIX
    z_map: Dict[int, List[Sig]] = defaultdict(list)
    for s in sigs:
        if s.z and s.z != 1 and s.z_state == "ok":
            z_map[s.z].append(s)

    hits = [(z, grp) for z, grp in z_map.items()
            if len(grp) >= 2 and len({g.r for g in grp}) >= 2]
    if not hits: return None

    evidence: Dict[str, Any] = {"reused_z_count": len(hits), "examples": []}
    for z, grp in hits[:5]:
        evidence["examples"].append({
            "z_hex":     f"{z:064x}",
            "sig_count": len(grp),
            "txids":     [f"{g.spend_txid}:{g.input_index}" for g in grp[:4]],
        })
    first_colliding_pk = hits[0][1][0].pubkey_hex  # BUG-V7 FIX
    return Finding(
        pubkey_hex = first_colliding_pk,
        vuln       = "sighash_reuse_pattern",
        severity   = VULN_SEVERITY["sighash_reuse_pattern"],
        confidence = min(0.95, 0.5 + len(hits)*0.1),
        evidence   = evidence,
        mitigation = ("Identical message hashes signed with different nonces. "
                      "Verify RFC 6979 uses unique entropy per signing key."),
    )


def detect_partial_nonce_leak(r_vals: List[int]) -> Optional[Finding]:
    if len(r_vals) < MIN_PART_LEAK: return None
    top_16 = [r >> 240 for r in r_vals]
    if len(set(top_16)) == 1:
        return Finding(
            pubkey_hex = "",
            vuln       = "strong_partial_nonce_leak",
            severity   = VULN_SEVERITY["strong_partial_nonce_leak"],
            confidence = 0.90,
            evidence   = {"constant_top_16_bits": f"{top_16[0]:04x}",
                          "sample_size": len(r_vals)},
            mitigation = "Top 16 bits of nonce constant. Lattice attack vulnerable. Rotate immediately.",
        )
    top_32 = [r >> 224 for r in r_vals]
    if len(set(top_32)) <= 2:
        return Finding(
            pubkey_hex = "",
            vuln       = "strong_hnp_partial_leak",
            severity   = VULN_SEVERITY["strong_hnp_partial_leak"],
            confidence = 0.75,
            evidence   = {"top_32_bits_unique": len(set(top_32)),
                          "sample_size": len(r_vals)},
            mitigation = "Severe partial nonce leakage. Bleichenbacher/lattice attack risk. Rotate key.",
        )
    return None


def detect_hnp_lattice_candidates(pk: str, sigs: List[Sig]) -> Optional[Finding]:
    if len(sigs) < MIN_HNP: return None
    r_vals = [s.r for s in sigs]
    is_weak, weak_ev = detect_weak_rng(r_vals)
    if not is_weak: return None

    confidence_base = weak_ev.get("confidence", 0.5)
    sample = sigs[:min(10, len(sigs))]
    vecs   = [[s.r%N, (-s.s)%N, s.z%N] for s in sample]

    def gram_schmidt(basis: List[List[int]]) -> List[List[float]]:
        gs: List[List[float]] = []
        for v in basis:
            u = [float(x) for x in v]
            for b in gs:
                num = sum(u[i]*b[i] for i in range(len(u)))
                den = sum(b[i]*b[i] for i in range(len(b)))
                if den > 0:
                    proj = num/den
                    u    = [u[i] - proj*b[i] for i in range(len(u))]
            gs.append(u)
        return gs

    gs_vecs       = gram_schmidt(vecs)
    orig_norms_sq = [sum(float(x)*float(x) for x in v) for v in vecs]
    gs_norms_sq   = [sum(u_i*u_i for u_i in u)         for u in gs_vecs]

    def _log_det(norms_sq: List[float]) -> float:
        total = 0.0
        for n in norms_sq:
            if n <= 0: return float("inf")
            total += 0.5 * math.log(n)
        return total

    log_orig = _log_det(orig_norms_sq)
    log_gs   = _log_det(gs_norms_sq)
    if log_gs == float("inf") or log_gs <= 0.0:
        defect = float("inf")
    else:
        log_defect = log_orig - log_gs
        defect = math.exp(min(log_defect, 700.0)) if log_defect < 700.0 else float("inf")

    lattice_confidence = min(1.0, math.log10(max(1.0, defect)) / 10.0)
    overall_confidence = min(1.0, (confidence_base + lattice_confidence) / 2.0 * 0.9)

    return Finding(
        pubkey_hex = pk,
        vuln       = "hnp_lattice_score",
        severity   = VULN_SEVERITY["hnp_lattice_score"],
        confidence = round(overall_confidence, 4),
        evidence   = {
            "reason":             "weak_nonce_entropy_with_lattice_structure",
            "rng_evidence":       weak_ev,
            "lattice_defect":     round(defect, 4) if defect != float("inf") else "inf",
            "lattice_confidence": round(lattice_confidence, 4),
            "sample_size":        len(sample),
        },
        mitigation = ("Weak nonce entropy + lattice structure -> HNP attack risk. "
                      "Rotate key immediately."),
    )


def detect_timing_side_channel(sigs: List[Sig]) -> Optional[Finding]:
    if not sigs or len(sigs) < 10: return None  # BUG-V4 FIX
    s_vals    = [s.s for s in sigs]
    mn, mx    = min(s_vals), max(s_vals)
    range_s   = mx - mn
    flags:   List[str]    = []
    evidence: Dict[str, Any] = {
        "s_range": range_s, "s_range_ratio": round(range_s/N, 8)}

    if range_s < N//100: flags.append("clustered_s_values")
    s_top       = [(s >> 248) & 0xFF for s in s_vals]
    s_top_uniq  = len(set(s_top))
    evidence["s_top_byte_unique"] = s_top_uniq
    if s_top_uniq == 1 and len(s_vals) > 10:
        flags.append("constant_s_top_byte")
    elif s_top_uniq <= 2 and len(s_vals) > 20:
        flags.append("very_low_s_top_byte_diversity")

    if not flags: return None
    evidence["flags"] = flags
    return Finding(
        pubkey_hex = sigs[0].pubkey_hex,
        vuln       = "timing_side_channel_indicator",
        severity   = VULN_SEVERITY["timing_side_channel_indicator"],
        confidence = 0.6,
        evidence   = evidence,
        mitigation = "Ensure constant-time scalar multiplication and modular reduction",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Security scoring
# ─────────────────────────────────────────────────────────────────────────────

def calculate_security_score(
    pk: str,
    findings: List[Finding],
) -> SecurityScore:
    score = SecurityScore(pubkey_hex=pk)
    for finding in findings:
        if finding.confidence < 0.2: continue
        deduction = int(finding.severity * finding.confidence)
        prev = score.vulnerability_scores.get(finding.vuln, 0)
        score.vulnerability_scores[finding.vuln] = max(prev, deduction)

    total_deduction = sum(score.vulnerability_scores.values())
    if total_deduction > 0:
        penalty = total_deduction / (1 + total_deduction / 100)
        score.total_score = max(0, min(100, int(100 - penalty)))
    else:
        score.total_score = 100

    # Recommendations
    if "nonce_reuse" in score.vulnerability_scores:
        score.recommendations.append(
            "CRITICAL: Private key recoverable from nonce reuse. Move all funds immediately.")
    if "cross_key_nonce_reuse" in score.vulnerability_scores:
        score.recommendations.append(
            "CRITICAL: Cross-key nonce reuse — global RNG compromise. Audit all keys from same source.")
    if ("strong_partial_nonce_leak" in score.vulnerability_scores
            or "strong_hnp_partial_leak" in score.vulnerability_scores):
        score.recommendations.append(
            "CRITICAL: Partial nonce leakage enables lattice key recovery. Rotate key immediately.")
    if "weak_rng" in score.vulnerability_scores:
        score.recommendations.append(
            "Replace RNG with a CSPRNG (OS /dev/urandom, getrandom, or RFC 6979).")
    if "biased_nonce" in score.vulnerability_scores:
        score.recommendations.append(
            "Nonce generation is statistically biased. Inspect nonce derivation path.")
    if "transaction_malleability" in score.vulnerability_scores:
        score.recommendations.append(
            "Implement low-S signature generation (BIP 62 / BIP 146 compliance).")
    if "nonce_correlation" in score.vulnerability_scores:
        score.recommendations.append(
            "Nonces are correlated. Ensure independent entropy per signing operation.")
    if "sighash_reuse_pattern" in score.vulnerability_scores:
        score.recommendations.append(
            "Sighash collision detected. Verify deterministic nonce uniqueness.")
    if "polynomial_nonce" in score.vulnerability_scores:
        score.recommendations.append(
            "CRITICAL: Nonces follow polynomial pattern. Key algebraically recoverable. Rotate.")
    if "lcg_nonce_pattern" in score.vulnerability_scores:
        score.recommendations.append(
            "CRITICAL: Nonces show LCG structure. Vulnerable to lattice recovery. Rotate.")
    if score.total_score <= 30:
        score.recommendations.append(
            "IMMEDIATE ACTION REQUIRED: Critical weaknesses detected. Assume compromise and rotate.")

    score.calculate_risk_level()
    return score


# ─────────────────────────────────────────────────────────────────────────────
# Detailed report writer
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_evidence(ev: Dict[str, Any], indent: int = 6) -> str:
    pad = " " * indent
    lines: List[str] = []
    for k, v in ev.items():
        if isinstance(v, dict):
            lines.append(f"{pad}{k}:")
            for kk, vv in v.items():
                lines.append(f"{pad}  {kk}: {vv}")
        elif isinstance(v, list):
            if len(v) <= 30:
                lines.append(f"{pad}{k}: [{', '.join(str(x) for x in v)}]")
            else:
                lines.append(f"{pad}{k}: [{', '.join(str(x) for x in v[:30])} ... ({len(v)} total items)]")
        else:
            lines.append(f"{pad}{k}: {v}")
    return "\n".join(lines)


def _write_detailed_report(
    path: str,
    load_stats: Dict[str, int],
    by_pk: Dict[str, List[Sig]],
    all_findings: List[Finding],
    security_scores: Dict[str, SecurityScore],
    sev_dist: Dict[str, int],
    risk_summary: Dict[str, int],
    findings_by_type: Counter[str],
    source_csv: str,
) -> None:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    SEP  = "=" * 78
    SEP2 = "-" * 78

    findings_by_pk: Dict[str, List[Finding]] = defaultdict(list)
    for f in all_findings:
        if f.vuln == "cross_key_nonce_reuse":
            affected = f.evidence.get("all_pubkeys", [f.pubkey_hex])
            for pk_affected in affected:
                findings_by_pk[pk_affected].append(f)
        else:
            findings_by_pk[f.pubkey_hex].append(f)

    risk_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "minimal": 4}
    sorted_pks = sorted(
        security_scores.keys(),
        key=lambda pk: (
            risk_rank.get(security_scores[pk].risk_level, 5),
            security_scores[pk].total_score,
            pk,
        ),
    )

    with open(path, "w", encoding="utf-8") as fh:
        def w(line: str = "") -> None:
            fh.write(line + "\n")

        w(SEP)
        w("  DOGECOIN ECDSA VULNERABILITY ANALYSIS — DETAILED REPORT")
        w(SEP)
        w(f"  Generated     : {now_str}")
        w(f"  Source CSV    : {source_csv}")
        w(f"  Signatures    : {load_stats['valid_sigs']} valid  "
          f"| {load_stats['invalid_sigs']} skipped  "
          f"| {load_stats['high_s']} high-S")
        w(f"  Pubkeys       : {len(security_scores)} analyzed")
        w(f"  Total findings: {len(all_findings)}")
        w(SEP)
        w()

        w("RISK LEVEL DISTRIBUTION")
        w(SEP2)
        for lvl in ("critical", "high", "medium", "low", "minimal"):
            cnt = risk_summary.get(lvl, 0)
            bar = "#" * min(cnt, 50)
            w(f"  {lvl:<10} {cnt:>5}  {bar}")
        w()
        w("SEVERITY DISTRIBUTION (findings)")
        w(SEP2)
        for lvl, cnt in sev_dist.items():
            bar = "#" * min(cnt, 50)
            w(f"  {lvl:<10} {cnt:>5}  {bar}")
        w()
        w("DETECTOR TRIGGER COUNTS (18 detectors)")
        w(SEP2)
        all_det_names = [
            "nonce_reuse", "duplicate_r", "cross_key_nonce_reuse",
            "small_k", "strong_partial_nonce_leak", "strong_hnp_partial_leak",
            "biased_nonce", "weak_rng", "deterministic_k_bug",
            "polynomial_nonce", "nonce_correlation", "lcg_nonce_pattern",
            "hnp_lattice_score", "transaction_malleability",
            "timing_side_channel_indicator", "entropy_deficiency",
            "bit_balance_anomaly", "sighash_reuse_pattern",
        ]
        for name in all_det_names:
            cnt = findings_by_type.get(name, 0)
            sev = VULN_SEVERITY.get(name, 0)
            flag = "  <<< TRIGGERED >>>" if cnt > 0 else ""
            w(f"  {name:<42} sev={sev:>3}  count={cnt:>4}{flag}")
        w()

        w("LOAD STATISTICS")
        w(SEP2)
        for k, v in load_stats.items():
            w(f"  {k:<35} : {v}")
        w()

        w(SEP)
        w("  PER-PUBKEY VULNERABILITY BREAKDOWN")
        w(SEP)
        w()

        shown = 0
        for pk in sorted_pks:
            sc = security_scores[pk]
            pk_findings = findings_by_pk.get(pk, [])
            if not pk_findings and sc.risk_level == "minimal":
                continue
            shown += 1

            sigs_for_pk = by_pk.get(pk, [])
            w(f"{'#' * 78}")
            w(f"  PUBKEY  : {pk}")
            w(f"  SCORE   : {sc.total_score}/100  |  RISK: {sc.risk_level.upper()}")
            w(f"  SIGS    : {len(sigs_for_pk)}  |  FINDINGS: {len(pk_findings)}")
            if sc.vulnerability_scores:
                w(f"  VULNS   : {', '.join(sc.vulnerability_scores.keys())}")
            w(SEP2)

            for fi in sorted(pk_findings, key=lambda x: -x.severity):
                sev_label = (
                    "CRITICAL" if fi.severity >= 90 else
                    "HIGH"     if fi.severity >= 70 else
                    "MEDIUM"   if fi.severity >= 50 else
                    "LOW"
                )
                w(f"  [{sev_label}] {fi.vuln}  "
                  f"severity={fi.severity}  confidence={fi.confidence:.2f}")
                if fi.mitigation:
                    w(f"    Mitigation: {fi.mitigation}")
                w("    Evidence:")
                ev_text = _fmt_evidence(fi.evidence, indent=6)
                if ev_text:
                    w(ev_text)

                rec_pairs = fi.evidence.get("recovered_pairs", [])
                if rec_pairs:
                    w("    RECOVERED KEY PAIRS:")
                    for pair in rec_pairs:
                        w(f"      sig1            : {pair.get('sig1','?')}")
                        w(f"      sig2            : {pair.get('sig2','?')}")
                        w(f"      recovered_priv  : {pair.get('recovered_priv_hex','?')}")
                        w(f"      recovered_k     : {pair.get('recovered_k_hex','?')}")
                        w(f"      verified        : {pair.get('verified', False)}")
                w()

            if sc.recommendations:
                w("  RECOMMENDATIONS:")
                for rec in sc.recommendations:
                    w(f"    * {rec}")
                w()

        if shown == 0:
            w("  No vulnerabilities detected across all pubkeys.")
            w()

        w()
        w(SEP)
        w("  APPENDIX: FULL SIGNATURE DATA FOR CRITICAL / HIGH RISK PUBKEYS")
        w(SEP)
        w()
        for pk in sorted_pks:
            sc = security_scores[pk]
            if sc.risk_level not in ("critical", "high"):
                continue
            sigs_for_pk = by_pk.get(pk, [])
            w(f"  PUBKEY: {pk}  |  SCORE: {sc.total_score}/100  |  RISK: {sc.risk_level.upper()}")
            w(f"  TOTAL SIGNATURES: {len(sigs_for_pk)}")
            w("  " + "-" * 74)
            for s in sigs_for_pk:
                w(f"    txid={s.spend_txid} vin={s.input_index} height={s.block_height} "
                  f"r={s.r:064x} s={s.s:064x} z={s.z:064x} s_high={s.s_high} sht={s.sighash_type}")
            w()

        w(SEP)
        w(f"  END OF REPORT  |  {shown} pubkeys with findings  |  {now_str}")
        w(SEP)

    logger.info("Detailed report written: %s  (%d pubkeys with findings)", path, shown)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Hardened ECDSA nonce-vulnerability detector  (Stage 3 of 3).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vuln.py signatures.csv
  python vuln.py signatures.csv --outdir ./reports --min-sigs 5
  python vuln.py signatures.csv --quick
        """)
    ap.add_argument("signatures_csv", help="CSV produced by signature.py")
    ap.add_argument("--outdir",   default=".", help="Output directory")
    ap.add_argument("--min-sigs", type=int, default=1,
                    help="Skip pubkeys with fewer than N signatures (default 1)")
    ap.add_argument("--quick",    action="store_true",
                    help="Skip computationally intensive checks (weak_rng, HNP)")
    ap.add_argument("--skip-detectors", metavar="NAME,...",
                    help="Comma-separated list of detectors to disable (e.g. weak_rng,hnp_lattice_score)")
    args = ap.parse_args()

    if not os.path.isfile(args.signatures_csv):
        logger.error("File not found: %s", args.signatures_csv)
        sys.exit(1)

    logger.info("Loading signatures from %s", args.signatures_csv)
    sigs, load_stats = load_sigs(args.signatures_csv)
    logger.info(
        "Loaded %d valid sigs (%d invalid, %d high-S, %d sighash-bug, "
        "%d missing_fields, %d unicode_replacements)",
        load_stats["valid_sigs"], load_stats["invalid_sigs"],
        load_stats["high_s"], load_stats["sighash_bug_skipped"],
        load_stats["missing_fields"], load_stats["unicode_replacements"])

    if not sigs:
        logger.error("No valid signatures to analyze."); sys.exit(1)

    by_pk: Dict[str, List[Sig]] = defaultdict(list)
    for sig in sigs:
        by_pk[sig.pubkey_hex].append(sig)

    by_pk.pop("", None)

    if args.min_sigs > 1:
        before = len(by_pk)
        by_pk  = {pk: v for pk, v in by_pk.items() if len(v) >= args.min_sigs}
        logger.info("Pubkeys: %d -> %d (with >= %d sigs)", before, len(by_pk), args.min_sigs)
    else:
        logger.info("Pubkeys: %d", len(by_pk))

    if not by_pk:
        logger.error("No pubkeys meet the minimum signature threshold."); sys.exit(1)

    all_findings:    List[Finding]            = []
    security_scores: Dict[str, SecurityScore] = {}

    # Phase 1
    logger.info("Phase 1: Nonce reuse and cross-key analysis...")
    f1, global_r_to_pks = detect_duplicate_r_and_nonce_reuse(by_pk)
    cross = detect_cross_key_nonce_reuse(global_r_to_pks, by_pk)
    all_findings.extend(f1)
    all_findings.extend(cross)

    phase1_by_pk: Dict[str, List[Finding]] = defaultdict(list)
    for f in f1:
        phase1_by_pk[f.pubkey_hex].append(f)
    for f in cross:
        affected = f.evidence.get("all_pubkeys", [f.pubkey_hex])
        for affected_pk in affected:
            if affected_pk in by_pk:
                phase1_by_pk[affected_pk].append(f)

    # Phase 2
    logger.info("Phase 2: Statistical analysis of %d pubkeys...", len(by_pk))

    skip_set = set((args.skip_detectors or "").split(",")) if args.skip_detectors else set()

    for idx, (pk, lst) in enumerate(by_pk.items(), 1):
        if idx % 100 == 0:
            logger.info("  Progress: %d/%d", idx, len(by_pk))

        has_heights = all(s.block_height > 0 for s in lst)
        if has_heights:
            ordered = sorted(lst, key=lambda s: (s.block_height, s.input_index))
        else:
            ordered = sorted(lst, key=lambda s: (s.spend_txid, s.input_index))
            if len(lst) >= MIN_CORR:
                logger.warning(
                    "Pubkey %s... lacks block-height; order-dependent detectors may be unreliable.",
                    pk[:16])

        r_vals = [s.r for s in ordered]
        z_vals = [s.z for s in ordered]
        key_findings: List[Finding] = []

        mal = detect_transaction_malleability(ordered)
        if mal: key_findings.append(mal)

        sk_ev = detect_small_k(ordered)
        if sk_ev:
            key_findings.append(Finding(
                pubkey_hex = pk,
                vuln       = "small_k",
                severity   = VULN_SEVERITY["small_k"],
                confidence = sk_ev.get("confidence", 0.5),
                evidence   = sk_ev,
                mitigation = "Ensure nonces are generated with >= 256 bits of entropy",
            ))

        is_biased, bias_ev = detect_biased_nonce(r_vals)
        if is_biased:
            key_findings.append(Finding(
                pubkey_hex = pk, vuln = "biased_nonce",
                severity   = VULN_SEVERITY["biased_nonce"], confidence = 0.8,
                evidence   = bias_ev,
                mitigation = "Use CSPRNG (e.g., /dev/urandom, getrandom syscall)",
            ))

        if not args.quick and "weak_rng" not in skip_set:
            is_weak, weak_ev = detect_weak_rng(r_vals)
            if is_weak:
                key_findings.append(Finding(
                    pubkey_hex = pk, vuln = "weak_rng",
                    severity   = VULN_SEVERITY["weak_rng"],
                    confidence = weak_ev.get("confidence", 0.7),
                    evidence   = weak_ev,
                    mitigation = "Audit and replace RNG; consider hardware entropy source",
                ))

        is_corr, corr_ev = detect_nonce_correlation(r_vals)
        if is_corr:
            key_findings.append(Finding(
                pubkey_hex = pk, vuln = "nonce_correlation",
                severity   = VULN_SEVERITY["nonce_correlation"], confidence = 0.85,
                evidence   = corr_ev,
                mitigation = "Ensure nonce generation produces independent values per signature",
            ))

        is_det, det_ev = detect_deterministic_k_bug(r_vals, z_vals)
        if is_det:
            key_findings.append(Finding(
                pubkey_hex = pk, vuln = "deterministic_k_bug",
                severity   = VULN_SEVERITY["deterministic_k_bug"], confidence = 0.75,
                evidence   = det_ev,
                mitigation = "Review RFC 6979 implementation for correctness",
            ))

        is_poly, poly_ev = detect_polynomial_nonce(r_vals, z_vals)
        if is_poly:
            key_findings.append(Finding(
                pubkey_hex = pk, vuln = "polynomial_nonce",
                severity   = VULN_SEVERITY["polynomial_nonce"],
                confidence = min(1.0, 0.7 + len(poly_ev.get("flags",[])) * 0.1),
                evidence   = poly_ev,
                mitigation = "Polynomial nonces -> algebraically recoverable. Rotate key.",
            ))

        is_lcg, lcg_ev = detect_lcg_nonce_pattern(r_vals)
        if is_lcg:
            key_findings.append(Finding(
                pubkey_hex = pk, vuln = "lcg_nonce_pattern",
                severity   = VULN_SEVERITY["lcg_nonce_pattern"],
                confidence = min(1.0, 0.65 + len(lcg_ev.get("flags",[])) * 0.1),
                evidence   = lcg_ev,
                mitigation = "LCG-structured nonces -> replace with CSPRNG or RFC 6979.",
            ))

        ent_f = detect_entropy_deficiency(r_vals)
        if ent_f: ent_f.pubkey_hex = pk; key_findings.append(ent_f)

        bal_f = detect_bit_balance_anomaly(r_vals)
        if bal_f: bal_f.pubkey_hex = pk; key_findings.append(bal_f)

        sr_f = detect_sighash_reuse(ordered)
        if sr_f: key_findings.append(sr_f)

        pnl_f = detect_partial_nonce_leak(r_vals)
        if pnl_f: pnl_f.pubkey_hex = pk; key_findings.append(pnl_f)

        if not args.quick and "hnp_lattice_score" not in skip_set:
            hnp_f = detect_hnp_lattice_candidates(pk, ordered)
            if hnp_f: key_findings.append(hnp_f)

        tsc_f = detect_timing_side_channel(ordered)
        if tsc_f: key_findings.append(tsc_f)

        all_key_findings = key_findings + phase1_by_pk.get(pk, [])
        score = calculate_security_score(pk, all_key_findings)
        security_scores[pk] = score
        all_findings.extend(key_findings)

    os.makedirs(args.outdir, exist_ok=True)

    critical_pks: Set[str] = {
        pk for pk, sc in security_scores.items() if sc.risk_level == "critical"}

    findings_by_type = Counter(f.vuln for f in all_findings)
    sev_dist = {
        "critical": len([f for f in all_findings if f.severity >= 90]),
        "high":     len([f for f in all_findings if 70 <= f.severity < 90]),
        "medium":   len([f for f in all_findings if 50 <= f.severity < 70]),
        "low":      len([f for f in all_findings if f.severity < 50]),
    }
    risk_summary = {lvl: sum(1 for s in security_scores.values() if s.risk_level == lvl)
                    for lvl in ("critical","high","medium","low","minimal")}

    report: Dict[str, Any] = {
        "vulnerability_analysis_report": {
            "analysis_info": {
                "total_signatures_analyzed": load_stats["valid_sigs"],
                "total_pubkeys_analyzed":    len(by_pk),
                "load_statistics":           load_stats,
                "analysis_date":             datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
            },
            "vulnerability_summary": {
                "total_findings":        len(all_findings),
                "findings_by_type":      dict(findings_by_type),
                "severity_distribution": sev_dist,
            },
            "pubkey_risk_summary": risk_summary,
            "critical_findings":    [],
            "recommendations":      [],
        }
    }

    seen_cf: Set[Tuple[str, str]] = set()
    for f in all_findings:
        if f.severity >= 90 or f.pubkey_hex in critical_pks:
            key = (f.pubkey_hex, f.vuln)
            if key in seen_cf: continue
            seen_cf.add(key)
            report["vulnerability_analysis_report"]["critical_findings"].append({
                "pubkey_hex":    (f.pubkey_hex[:16] + "..." if len(f.pubkey_hex) > 16
                                  else f.pubkey_hex),
                "vulnerability": f.vuln,
                "severity":      f.severity,
                "confidence":    f.confidence,
                "mitigation":    f.mitigation,
            })

    recs = report["vulnerability_analysis_report"]["recommendations"]
    if any(s.risk_level in ("critical","high") for s in security_scores.values()):
        recs.append("IMMEDIATE ACTION: One or more keys critically compromised. Rotate funds.")
    if load_stats["high_s"] > 0:
        recs.append("Implement low-S signature generation to prevent transaction malleability.")
    if load_stats["sighash_bug_skipped"] > 0:
        recs.append(f"{load_stats['sighash_bug_skipped']} sigs had SIGHASH_SINGLE bug; verify manually.")
    if not recs:
        recs.append("No immediate action required. Continue periodic key-health monitoring.")

    # Write output files
    findings_path = os.path.join(args.outdir, "detector_findings.json")
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump({"findings": [asdict(f) for f in all_findings],
                   "summary":  report["vulnerability_analysis_report"]},
                  f, indent=2, default=str)

    recovered_keys_path = os.path.join(args.outdir, "recovered_keys.csv")
    with open(recovered_keys_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["pubkey_hex", "r_hex", "sig1", "sig2", "recovered_priv_hex", "recovered_k_hex", "verified"])
        for finding in all_findings:
            if finding.vuln == "nonce_reuse":
                for pair in finding.evidence.get("recovered_pairs", []):
                    w.writerow([
                        finding.pubkey_hex,
                        finding.evidence.get("r_hex", ""),
                        pair.get("sig1", ""),
                        pair.get("sig2", ""),
                        pair.get("recovered_priv_hex", ""),
                        pair.get("recovered_k_hex", ""),
                        pair.get("verified", False),
                    ])

    scores_path = os.path.join(args.outdir, "security_scores.csv")
    with open(scores_path, "w", newline="", encoding="utf-8") as f:
        fields = ["pubkey_hex","total_score","risk_level","vulnerabilities","recommendations"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for pk_key, sc in security_scores.items():
            w.writerow({
                "pubkey_hex":      pk_key,
                "total_score":     sc.total_score,
                "risk_level":      sc.risk_level,
                "vulnerabilities": "; ".join(sc.vulnerability_scores.keys()),
                "recommendations": "; ".join(sc.recommendations),
            })

    report_path = os.path.join(args.outdir, "vulnerability_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    detail_path = os.path.join(args.outdir, "detailed_report.txt")
    _write_detailed_report(
        detail_path, load_stats, by_pk, all_findings, security_scores,
        sev_dist, risk_summary, findings_by_type, args.signatures_csv)

    # Console summary
    logger.info("=" * 70)
    logger.info("VULNERABILITY ANALYSIS COMPLETE")
    logger.info("=" * 70)
    logger.info("Signatures analyzed  : %d", load_stats["valid_sigs"])
    logger.info("Pubkeys analyzed     : %d", len(by_pk))
    logger.info("Total findings       : %d", len(all_findings))
    logger.info("-" * 70)

    all_det_names = [
        "nonce_reuse","duplicate_r","cross_key_nonce_reuse",
        "small_k","strong_partial_nonce_leak","strong_hnp_partial_leak",
        "biased_nonce","weak_rng","deterministic_k_bug",
        "polynomial_nonce","nonce_correlation","lcg_nonce_pattern",
        "hnp_lattice_score","transaction_malleability",
        "timing_side_channel_indicator","entropy_deficiency",
        "bit_balance_anomaly","sighash_reuse_pattern",
    ]
    logger.info("DETECTOR RESULTS (18 total):")
    for name in all_det_names:
        count  = findings_by_type.get(name, 0)
        sev    = VULN_SEVERITY.get(name, 0)
        marker = "  *** TRIGGERED ***" if count > 0 else ""
        logger.info("  %-42s sev=%3d  count=%d%s", name, sev, count, marker)

    logger.info("-" * 70)
    logger.info("SEVERITY:  critical=%d  high=%d  medium=%d  low=%d",
                sev_dist["critical"], sev_dist["high"],
                sev_dist["medium"],   sev_dist["low"])
    logger.info("RISK LVLS: critical=%d  high=%d  medium=%d  low=%d  minimal=%d",
                risk_summary["critical"], risk_summary["high"],
                risk_summary["medium"],  risk_summary["low"],
                risk_summary["minimal"])

    crit = report["vulnerability_analysis_report"]["critical_findings"]
    if crit:
        logger.info("-" * 70)
        logger.info("CRITICAL FINDINGS (%d, showing up to 20):", len(crit))
        for cf in crit[:20]:
            logger.info("  [%s] %s  sev=%d  conf=%.2f",
                        cf["pubkey_hex"], cf["vulnerability"],
                        cf["severity"],  cf["confidence"])
            if cf.get("mitigation"):
                logger.info("    -> %s", cf["mitigation"])

    for r in recs:
        logger.info("  * %s", r)

    logger.info("=" * 70)
    logger.info("OUTPUT FILES:")
    logger.info("  Vulnerability report : %s", report_path)
    logger.info("  All findings (JSON)  : %s", findings_path)
    logger.info("  Security scores (CSV): %s", scores_path)
    logger.info("  Detailed report (TXT): %s", detail_path)
    logger.info("  Recovered keys (CSV) : %s", recovered_keys_path)


if __name__ == "__main__":
    main()