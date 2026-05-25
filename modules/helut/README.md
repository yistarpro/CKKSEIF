# HELUT — Privacy-Preserving Embedding via Look-up Table Evaluation

Implementation of:

> Kim, Park, Lee, Cheon. *Privacy-Preserving Embedding via Look-up Table Evaluation with Fully Homomorphic Encryption*. ICML 2024.

## What's here

| File | Contents |
|---|---|
| `include/ckkseif/helut/embedding.h` + `src/embedding.cpp` | The `CompressedEmbedding` and `LogregModel` classes (Paper §2.2). |
| `include/ckkseif/helut/lookup.h` + `src/lookup.cpp` | Look-up table evaluation routines and the encrypted logistic-regression inference pipeline. |
| `include/ckkseif/helut/test_helut.h` + `tests/test_helut.cpp` | Benchmarks: `LUTLTTest`, `LUTCITest`, `CodedLUTTest`, `CodedLUTSIMDTest`, `LUTSynthTests`, `EmbeddingTest(s)`, `EmbeddingSIMDTest(s)`, `LogregTest`, `LogregSIMDTest`, `LogregTestPlain`. |
| `exp/main_helut.cpp` | Entry point for `bench_helut`. |

## Key functions (Paper 1 ↔ code)

| Paper | Code |
|---|---|
| HELUT-LT (Eq. 9) — linear-transformation LUT | `HELUT_LT` |
| HELUT-CI (Alg 3) — coded-input LUT | `HELUT_CI` |
| CodedHELUT (Alg 4) — coded-compression LUT | `CodedHELUT` |
| CodedHELUT + **p1** SIMD parallelization | `CodedHELUT_P1` |
| Client-side ciphertext encoding | `EncryptForSIMD` |
| Sentence encoding | `EncryptSentence`, `EncryptSentenceSIMD` |
| Inference (encrypted) | `InferenceEncrypted`, `InferenceEncryptedSIMD` |
| Inference (plaintext baseline) | `InferencePlain`, `SentenceEmbeddingPlain` |

## CLI flags (`bench_helut --help`)

```
--lutsynth          Synthetic-table LUT benchmark (Paper 1 Table 1).
--embedding         CodedHELUT on GloVe / BERT / GPT-2 embeddings (Table 2).
--logreg            Encrypted logistic regression on top of CodedHELUT.
--emball            Run all of the above plus the underlying EIF benchmarks.
--iteration N       Repetitions per data point (default 8).
```

## Data

Compressed embeddings for GloVe / BERT / GPT-2 — see
[`../../data/README.md`](../../data/README.md). `CompressedEmbedding`'s
default paths assume `data/6B50d8_8wordtoindex.txt`,
`data/6B50d8_8weight.txt`, `data/6B50d8_8logreg.txt`.

## Depends on

`core/` only. Independent of `modules/hecount/` and `modules/privtopk/`.
