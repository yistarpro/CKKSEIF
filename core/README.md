# ckkseif-core

Shared library used by all three CKKSEIF apps. Depends on OpenFHE only.

## What lives here

| File | Contents |
|---|---|
| `include/ckkseif/eif.h` + `src/eif.cpp` | EIF / EEF primitives: `EEF` (the proposed equality function, parametric), `EEFSIMD`, `EEFBinary`, `Cleanse`, `ZeroTest`. Parameter selection helpers: `ParamSqMethod`, `ParamEEF`, `ParamZeroTest`. EIF generators: `GenEEFChecker*`. Alternative indicators from HELUT §D.3.1: `IndicatorBySinc`, `IndicatorByLagrange`. Shared rotation-key helper `AddRotKeyForEmb`. |
| `include/ckkseif/arithmetic.h` + `src/arithmetic.cpp` | Encrypted Sign Function (ESF) family: `ESF` (convenience), `EncryptedSignFunction` (parametric, takes `degf`/`degg`), `ESFQ`/`ESFQReconstruct` (quantized). Bootstrap wrappers (`BootAuto`, `BootWithPrec`, `FakeBoot`), evaluation helpers (`EvalLog`, `EvalLogLike`, `EvalInverse`, `Product`), input normalization (`Normalize`), and the `RotSum` primitive. Po2 rotation-key generation (`AddRotKeyForPo2`, `GenIdxForRotsum`, `GenIdxForMultiples`). |
| `include/ckkseif/utils.h` + `src/utils.cpp` | Packing helpers (`fullCopy`, `repeat`), CKKS context setup (`bootSet1`, `bootSet2`, `paramcheck`), file I/O for embeddings/datasets, RNG (`randomDiscreteArray*`, `randomRealArray`), precision-checking helpers. |
| `include/ckkseif/algorithms.h` | Slim umbrella header — `#include`s `eif.h` and `arithmetic.h`. Maintained for backward compatibility with older `#include "algorithms.h"` call sites. Apps that need PrivTopk-specific symbols must include the privtopk headers explicitly. |
| `tests/test_core.cpp` + `include/ckkseif/test_core.h` | Benchmarks: `EEFTest(s)`, `EEFSIMDTest`, `EEFTestDepth30`, `AnotherIndicatorTests`, `IndicatorBySincTest`, `IndicatorByLagrangeTest`, `IndicatorByESFTest`, `ESFTest(s)`, `ESFQTest`, `bootTest(2)`, `logTest`, plus the shared `statTime` helper. |
| `exp/main_core.cpp` | Entry point for the `bench_core` executable — a small flag dispatcher (`--indicator`, `--anotherindicator`, `--esf`, `--esfq`, `--iteration N`). |

## Naming conventions used here

- **EEF** = Encrypted Equality Function (the proposed EIF from HELUT — `Cleanse ∘ SqMethod`).
- **ESF** = Encrypted Sign Function (PrivTopk §II-B (uses CKK19 sign function)). Convenience wrapper is `ESF(ct, bound)`; parametric form is `EncryptedSignFunction(ct, degf, degg, bound, ver)`.
- **Quantized** suffix is **`_Q`** in the ESF family (`ESFQ`, `ESFQReconstruct`). The PrivTopk family uses **`_Arb`** instead — see [`modules/privtopk/README.md`](../modules/privtopk/README.md).

Depends on: OpenFHE only. Used by: `modules/helut`, `modules/hecount`, `modules/privtopk`.
