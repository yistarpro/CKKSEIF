CKKSEIF - Library of Encrypted Indicator Function on CKKS scheme
=====================================

This repository is an implementation of the Encrypted Indicator Function and its applications, on the following works:


* [KPLC24] Jae-yun Kim, Saerom Park, Joohee Lee, Jung Hee Cheon: Privacy-preserving embedding via look-up table evaluation with fully homomorphic encryption. Forty-first International Conference on Machine Learning, 2024. [Link]

```
@inproceedings{2024embedding,
  title={Privacy-preserving embedding via look-up table evaluation with fully homomorphic encryption},
  author={Kim, Jae-yun and Park, Saerom and Lee, Joohee and Cheon, Jung Hee},
  booktitle={Proceedings of the 41st International Conference on Machine Learning},
  pages={24437--24457},
  year={2024}
}
```

[Link]:https://openreview.net/forum?id=apxON2uH4N



* [KYCP24] Jae-yun Kim, Jieun Yun, Jung Hee Cheon, Saerom Park: Efficient Privacy-Preserving Counting Method with Homomorphic Encryption. 27th International Conference on Information Security and Cryptology, 2024.

```
@inproceedings{2024counting,
  title={Efficient Privacy-Preserving Counting Method with Homomorphic Encryption},
  author={Kim, Jae-yun and Yun, Jieun and Cheon, Jung Hee and Park, Saerom},
  booktitle={27th International Conference on Information Security and Cryptology (ICISC)},
  year={2024}
}
```


The encrypted sign function (`bench_core --esf` / `--esfq`) is the composite-polynomial method from Cheon, Kim, Kim - *Numerical Method for Comparison on Homomorphically Encrypted Numbers*, Asiacrypt 2019 (cited inline as **CKK19**).


## Installation

This code is based on OpenFHE
* [OpenFHE documentation](https://openfhe-development.readthedocs.io/en/latest/)
* [Design paper for OpenFHE](https://eprint.iacr.org/2022/915)
* [OpenFHE website](https://openfhe.org)

Note our implementation is on version 1.2.3. A helper installation script for prerequisite components is provided:

```
bash scripts/install_openfhe.sh
```

After installing OpenFHE, get data from the following link:

* https://drive.google.com/file/d/17YVk3uR_Q25j0ebJzyrblDupi1aMtwhz/view?usp=sharing

These data contain compressed embedding, indices for the embedding, parameter of logistic regression, and some documents for test input. They are obtained by running the following repository:

* https://github.com/yistarpro/compositional_code_learning

Put the files in `data` folder. The TF-IDF data for the information retrieval experiment is included in the linked archive as well. See `data/README.md` for the per-file format and the list of required artifacts.

Then build the project:

```
mkdir build
cd build
cmake ..
make -j$(nproc)
cd ..
```

This produces four executables in `build/`:

| Binary | Drives |
|---|---|
| `bench_core` | EIF / EEF / ESF benchmarks from [KPLC24] §3, App. E |
| `bench_helut` | Encrypted LUT, embedding, and logistic regression from [KPLC24] |
| `bench_hecount` | Counting, n-gram, TF-IDF / IR from [KYCP24] |
| `bench_parity` | Parity / bit-decomposition playground (not paper-attributed) |


## Options for Various Tests

Each binary takes `--iteration N` for the number of iterations per benchmark (default 8) and `--help` for the usage banner. All binaries are flag-dispatch style.

Example:

* `./build/bench_core --iteration 8 --indicator`
* `./build/bench_helut --lutsynth --embedding --logreg`
* `./build/bench_hecount --info`

Most benchmarks take minutes to hours per run; use `--iteration 1` for a quick sanity check.


### Tests for Encrypted Indicator Function - `bench_core` ([KPLC24] §3, App. E)

- `--indicator`
EEF (Encrypted Indicator Function) tests at scaling factors 35 and 50. Sweeps the indicator round parameters from `ParamEEF`.

- `--anotherindicator`
To compare other design choices, we implemented various indicator functions, including approximate comparison (CKK19-based), sinc approximation, and Lagrange interpolation. ([KPLC24] §D.3.1.)

- `--esf`
Encrypted Sign Function precision sweep at log Δ = 50 over a range of polynomial-degree schedules. (CKK19; used by [KPLC24] App. E.4.)

- `--esfq`
Quantized arbitrary-precision ESF at log Δ = 49 for 32-bit and 16-bit total precision (4-bit segments). (CKK19 quantized variant.)

- `--boot`
CKKS bootstrap micro-benchmark. Runs the sparse-ternary `bootTest` configuration and the OpenFHE-template `bootTest2` configuration in sequence.

- `--log`
`EvalLog` micro-benchmark at bound=2.0, degree=10. Used by the IDF stage of [KYCP24].


### Tests for Encrypted Embedding Layer - `bench_helut` ([KPLC24])

- `--lutsynth`
Tests for various constructions of encrypted LUT (HELUT-LT, HELUT-CI, CodedHELUT, CodedHELUT+p1), on Z^64 to R^16. ([KPLC24] Table 1.)

- `--embedding`
Tests for encrypted embedding layer of GloVe6B50d, GloVe42B300d, GPT-2. ([KPLC24] Table 2.)

- `--logreg`
Tests for encrypted logistic regression on GloVe6B50d, GloVe42B300d. ([KPLC24] App. E.2.) Resumable: skips configs that already have results in `logreg_result.txt`.

- `--emball`
Conduct all of `--lutsynth`, `--embedding`, `--logreg`, plus the underlying `--indicator` and `--anotherindicator` benchmarks from `bench_core`. These are all tests from [KPLC24].


### Tests for Encrypted Counting Algorithm - `bench_hecount` ([KYCP24])

- `--count`
Tests for various constructions of encrypted counting algorithm: NaiveCount (Alg 1) and CodedCount (Alg 2 / Alg 5 with BasisExp), on vocabulary size 256 and 256 arrays of size 256. ([KYCP24] Table 2.)

- `--paralcount`
Tests for the parallelized encrypted counting algorithm (ParalCount, Alg 7) on vocabulary size 256 and various numbers of arrays of size 256. ([KYCP24] Table 3.)

- `--ngram`
Tests for 2-gram and 3-gram extraction on vocabulary sizes 16 and 64. ([KYCP24] Table 4.)

- `--info`
Tests for E2EE information retrieval algorithm on the Amazon Fine Food Reviews dataset. ([KYCP24] §5.2 / Table 5.) Runs a CodedCountSIMD warm-up (for TF acquisition cost) plus three corpus sizes of `InfoRetrievalAfterTFTest`.

- `--countall`
Conduct all of above, which are all tests from [KYCP24].


### Auxiliary Tests - `bench_parity`

- `--parity`
ParityBySin smoke test. Domain Z_{2^d} for d=8, Chebyshev order K=8, log Δ = 35.

- `--bd`
Bit-decomposition smoke test (`ExtractLSBs`). Bound=256, log Δ = 50.

Both are single-shot smoke tests, not paper-attributed.


## Note on Structure of the Library

The repository is organized as `core/` (shared primitives) plus per-paper modules under `modules/`:

```
ckkseif/
├── core/                          # libckkseif-core: EIF/EEF, ESF, RotSum, bench helpers
│   ├── include/ckkseif/{eif,arithmetic,utils,bench_runner,test_core,algorithms}.h
│   ├── src/{eif,arithmetic,utils,bench_runner}.cpp
│   ├── tests/test_core.cpp        # EEF/ESF/boot/log/Indicator-baseline benchmarks
│   └── exp/main_core.cpp          # bench_core entry point
├── modules/
│   ├── helut/                     # [KPLC24]
│   ├── hecount/                   # [KYCP24]
│   └── parity/                    # paperless playground
├── scripts/
│   └── install_openfhe.sh
├── data/                          # download-only; see data/README.md
```

Files within each module follow the same shape:

- `include/`: public headers used by other modules and by the bench drivers.
- `src/`: the algorithms specified in the corresponding paper.
- `tests/`: test pipelines (CKKS setup + benchmark loop) for the algorithms.
- `exp/`: the `main_*.cpp` dispatcher that wires CLI flags to test functions.

Helpers used across all test/benchmark code (`makeCKKSContext`, `parseIteration`, `printBenchHeader`, `statTime`, RNG, precision-check) live in `core/{include,src}/.../bench_runner.{h,cpp}`. Library code (`core/src/eif.cpp`, `core/src/arithmetic.cpp`, `core/src/utils.cpp`, the per-module `src/*.cpp`) does not depend on `bench_runner`.


## Parameters

The CKKS parameters are specified in each paper, but the batch size is the same across all implementations: **2^16**. Multiplicative depth, scaling-modulus size, ring dimension, and security level are set per-test in the corresponding `*Test` function.

Most of the algorithms utilize coded input (Discrete Vector); the following are the major variables specifying the domain / codomain of the algorithms:

- `bound`: size of domain, `p` in the papers.
- `numcode`: number of codebooks, `l` in the papers.
- `outputdimension`: dimension of the embedding layer.
- `scaleModSize`: log₂ of the CKKS scaling factor (log Δ in the papers).
- `multDepth`: multiplicative depth budget for the CKKS context.


## License

Apache 2.0 - see [LICENSE](LICENSE).
