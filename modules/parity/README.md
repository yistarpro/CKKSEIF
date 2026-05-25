# parity — Parity and Bit-Decomposition Primitives

This module groups the parity / bit-extraction primitives that are not
attributed to any of the three currently-published CKKSEIF papers. It was
re-added as a separate module after the initial Phase-0 deletion so the
routines stay available as building blocks for future work.

## What's here

| File | Contents |
|---|---|
| `include/ckkseif/parity/parity.h` + `src/parity.cpp` | `Parity`, `ParityBySin`, `ExtractMSB`, `ExtractLSB`, `ExtractMSBs`, `ExtractLSBs`, `DecompToBits`, `BitsToOHE`, `BitsToOHESIMD`, plus the sign-function approximation `compandUp` used by `ExtractMSB` / `ExtractLSB`. |
| `tests/` | Empty — add `test_parity.cpp` here if you want benchmarks. The pre-reorg code had a commented-out `ParityTest` in `testcode.cpp` that could be re-enabled. |
| `exp/` | Empty — add `main_parity.cpp` if you want a `bench_parity` binary. |

## Functions

| Name | Description |
|---|---|
| `Parity(ct, d)` | Top-level parity function (depth-`d`). Internally combines `ParityBySin` with `Cleanse` from core/eif. |
| `ParityBySin(ct, d, K)` | Sinc / cosine product approximation (Chebyshev order `K`). |
| `ExtractMSB(ct, bound)` | Most-significant-bit extraction using `compandUp`. |
| `ExtractLSB(ct, bound)` | Least-significant-bit extraction (`ParityBySin` + Cleanse). |
| `ExtractMSBs(ct, bound, iter)` | Iterative MSB extraction down to `iter` bits. |
| `ExtractLSBs(ct, bound, iter)` | Iterative LSB extraction up to `iter` bits. |
| `DecompToBits(ct, boundbits, maxdepth)` | Full bit-decomposition. |
| `BitsToOHE(bits)` | Convert per-bit ciphertexts to one-hot. |
| `BitsToOHESIMD(bits, size)` | SIMD-packed variant of `BitsToOHE`. |
| `compandUp(ct, bound, boot, up)` | Polynomial sign-function variant used by the MSB/LSB extractors. |

## Depends on

- `core/` — uses `Cleanse` (from `core/include/ckkseif/eif.h`) and `RotSum`
  (from `core/include/ckkseif/arithmetic.h`).
- OpenFHE for the underlying CKKS operations.

Independent of `modules/helut`, `modules/hecount`, `modules/privtopk`.

## Status

The parity routines compile and link into a `ckkseif_parity` object library
but are **not yet driven by any benchmark** in this repository. There is no
`bench_parity` executable in the default build because the original
`ParityTest` body was commented out before the reorganization.

To wire one up:

1. Create `tests/test_parity.cpp` with one or more benchmark functions
   (e.g., `ParityTest`, `ExtractMSBTest`).
2. Create a header `include/ckkseif/parity/test_parity.h` with their
   declarations.
3. Create `exp/main_parity.cpp` as a flag-dispatch main calling those
   tests.
4. Add corresponding `add_library(ckkseif_parity_tests OBJECT ...)` and
   `add_executable(bench_parity ...)` blocks to the top-level
   `CMakeLists.txt`.
