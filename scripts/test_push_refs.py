#!/usr/bin/env python3
"""Unit tests for the push-ref scanner in radiant_preimage_oracle.

Validates the algorithm against hand-constructed scripts before we pull a real
Glyph mainnet tx for end-to-end fixture validation. Mirrors radiantjs
Script.getPushRefsFromScriptBuffer (lib/script/script.js:106-180) and the
GetHashOutputHashes refsHash computation (lib/transaction/sighash.js:104-123).
"""

import sys
from radiant_preimage_oracle import (
    OP_PUSHINPUTREF, OP_REQUIREINPUTREF, OP_DISALLOWPUSHINPUTREF,
    OP_PUSHINPUTREFSINGLETON, OP_PUSHDATA1, OP_PUSHDATA2,
    REF_LEN, ZERO_32,
    get_push_refs_from_script, compute_refs_hash, per_output_summary,
    sha256d, Output, u64_le, u32_le,
)

GREEN = "\033[92m"; RED = "\033[91m"; END = "\033[0m"
fails = 0


def check(name, cond, detail=""):
    global fails
    if cond:
        print(f"  {GREEN}✓{END} {name}")
    else:
        print(f"  {RED}✗{END} {name}  {detail}")
        fails += 1


# ---------- Test 1: plain P2PKH has no refs (regression) ----------
print("Test 1: plain P2PKH has zero push-refs")
p2pkh = bytes.fromhex("76a914") + b"\x00" * 20 + bytes.fromhex("88ac")
push, req, dis = get_push_refs_from_script(p2pkh)
check("no push refs", push == [])
check("no require refs", req == [])
check("no disallow refs", dis == [])
n, h = compute_refs_hash(push)
check("totalRefs == 0", n == 0)
check("refsHash == zero32", h == ZERO_32)


# ---------- Test 2: single OP_PUSHINPUTREF ----------
print("\nTest 2: single OP_PUSHINPUTREF")
ref_a = bytes.fromhex("aa" * 32 + "01000000")  # 36 bytes
script = bytes([OP_PUSHINPUTREF]) + ref_a + bytes.fromhex("76a914") + b"\x00" * 20 + bytes.fromhex("88ac")
push, req, dis = get_push_refs_from_script(script)
check("one push ref", len(push) == 1 and push[0] == ref_a)
n, h = compute_refs_hash(push)
check("totalRefs == 1", n == 1)
check("refsHash == sha256d(ref_a)", h == sha256d(ref_a))


# ---------- Test 3: multiple refs, dedupe + sort ----------
print("\nTest 3: multiple refs, dedupe + sort")
ref_high = bytes.fromhex("ff" * 32 + "00000000")
ref_low = bytes.fromhex("00" * 32 + "00000000")
ref_mid = bytes.fromhex("80" * 32 + "00000000")
# Insert in non-sorted order, with a duplicate of ref_high
script = (bytes([OP_PUSHINPUTREF]) + ref_high
          + bytes([OP_PUSHINPUTREF]) + ref_low
          + bytes([OP_PUSHINPUTREFSINGLETON]) + ref_mid
          + bytes([OP_PUSHINPUTREF]) + ref_high)
push, req, dis = get_push_refs_from_script(script)
check("4 raw push refs (incl dup)", len(push) == 4)
n, h = compute_refs_hash(push)
check("totalRefs == 3 after dedupe", n == 3, f"got {n}")
expected = sha256d(ref_low + ref_mid + ref_high)
check("refsHash == sha256d(low|mid|high)", h == expected)


# ---------- Test 4: REQUIREINPUTREF doesn't count toward totalRefs ----------
print("\nTest 4: REQUIREINPUTREF excluded from totalRefs")
ref_r = bytes.fromhex("11" * 32 + "02000000")
script = bytes([OP_REQUIREINPUTREF]) + ref_r + bytes.fromhex("76a914") + b"\x00" * 20 + bytes.fromhex("88ac")
push, req, dis = get_push_refs_from_script(script)
check("zero push refs", push == [])
check("one require ref", req == [ref_r])
n, h = compute_refs_hash(push)
check("totalRefs == 0", n == 0)
check("refsHash == zero32 (no push refs)", h == ZERO_32)


# ---------- Test 5: DISALLOW conflict raises ----------
print("\nTest 5: disallowed ref + push of same ref → raise")
ref_x = bytes.fromhex("dd" * 32 + "00000000")
script = bytes([OP_PUSHINPUTREF]) + ref_x + bytes([OP_DISALLOWPUSHINPUTREF]) + ref_x
try:
    get_push_refs_from_script(script)
    check("conflict detected", False, "did not raise")
except ValueError as e:
    check("conflict detected", "Disallowed ref appears" in str(e))


# ---------- Test 6: PUSHDATA opcodes don't break parser ----------
print("\nTest 6: PUSHDATA1 / PUSHDATA2 / direct-push correctly skipped")
data = b"\x42" * 100
ref_y = bytes.fromhex("ee" * 32 + "00000000")
script = (bytes([0x05]) + b"hello"                          # direct push 5
          + bytes([OP_PUSHDATA1, len(data)]) + data         # PUSHDATA1 100
          + bytes([OP_PUSHDATA2]) + b"\x10\x00" + b"\x00" * 16  # PUSHDATA2 16
          + bytes([OP_PUSHINPUTREF]) + ref_y)
push, _, _ = get_push_refs_from_script(script)
check("ref recovered after pushdata salad", push == [ref_y])


# ---------- Test 7: per_output_summary integrates correctly ----------
print("\nTest 7: per_output_summary layout for Glyph output")
spk = bytes([OP_PUSHINPUTREF]) + ref_a + bytes.fromhex("76a914") + b"\x00" * 20 + bytes.fromhex("88ac")
out = Output(value=12345, script_pubkey=spk)
summary = per_output_summary(out)
check("summary is 76 bytes", len(summary) == 76)
check("nValue prefix", summary[0:8] == u64_le(12345))
check("scriptHash slot", summary[8:40] == sha256d(spk))
check("totalRefs == 1", summary[40:44] == u32_le(1))
check("refsHash == sha256d(ref_a)", summary[44:76] == sha256d(ref_a))


print()
if fails == 0:
    print(f"{GREEN}All push-ref tests PASS.{END}")
    sys.exit(0)
else:
    print(f"{RED}{fails} test(s) FAILED.{END}")
    sys.exit(1)
