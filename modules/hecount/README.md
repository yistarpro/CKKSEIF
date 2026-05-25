# HECount — Privacy-Preserving Counting + TF-IDF + Information Retrieval

Implementation of:

> Kim, Yun, Cheon, Park. *Efficient Privacy-Preserving Counting Method with Homomorphic Encryption*. ICISC 2024.

## What's here

| File | Contents |
|---|---|
| `include/ckkseif/hecount/counting.h` + `src/counting.cpp` | Counting algorithms, n-gram extraction, and the TF-IDF / information-retrieval pipeline. |
| `include/ckkseif/hecount/test_count.h` + `tests/test_count.cpp` | Benchmarks: `NaiveCountTest`, `CodedCountTest`, `CodedCountSIMDTest`, `NgramTest`, `InfoRetrievalTest`, `InfoRetrievalAfterTFTest`. |
| `exp/main_hecount.cpp` | Entry point for `bench_hecount`. |

## Key functions (Paper 2 ↔ code)

| Paper | Code |
|---|---|
| NaiveCount (Alg 1) | `NaiveCount`, `NaiveCountSIMD`, `NaiveCountPartial` |
| Count = Coded Counting (Alg 2) | `Count`, `CountPartial` |
| ParalCount (Alg 7) — parallel counted | `ParalCount` |
| DimDecomp (Alg 3) | `DimDecomp` |
| BasisExp / BasisExpBlock (Alg 4) | `BasisExp`, `BasisExpBlock` |
| ParalBasisExp / ParalBasisExpBlock (Alg 6) | `ParalBasisExp`, `ParalBasisExpBlock` |
| FullBasis (App. 1.B) | `FullBasis` |
| OHE materialization | `ToOHE`, `ToOHESIMD` |
| IDF / IDF multiplication | `IDF`, `IDFMult` |
| n-gram basis / n-gram | `NgramBasis`, `Ngram` |
| Distance comparison (Eq. 12) | `DistanceComparison` |
| Retrieval | `Retrieval` |
| TF-IDF plaintext precomputation | `PrecomputeTFIDF` |
| Indicator-checker for the parallel counter | `GenIndicatorCheckerForSIMDCOUNT` (lives in `counting.cpp`, not core, since only this app uses it) |
| Dataset loaders | `LoadText`, `LoadTFIDF`, `LoadIDF`, `LoadQuery`, `LoadQueryTF` |

## CLI flags (`bench_hecount --help`)

```
--count             NaiveCount and CodedCount benchmarks.
--ngram             n-gram extraction benchmarks (n = 2, 3).
--info              IR pipeline on Amazon Fine Food Reviews.
--paralcount        Parallelized CodedCount benchmarks (CodedCountSIMD).
--countall          Run all of the above.
--iteration N       Repetitions per data point (default 8).
```

## Data

Amazon Fine Food Reviews — see
[`../../data/README.md`](../../data/README.md) for the Kaggle link.

## Depends on

`core/` only. Independent of `modules/helut/` and `modules/privtopk/`.
