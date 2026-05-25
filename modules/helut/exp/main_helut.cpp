#define PROFILE

#include "openfhe.h"
#include "test_helut.h"
#include "test_core.h"      // EEFTests / AnotherIndicatorTests (cross-paper EIF baselines)
#include "bench_runner.h"

#include <iostream>
#include <getopt.h>

using namespace lbcrypto;
using namespace std;
using namespace ckkseif;

static void usage(const char *prog) {
    cerr <<
        "Usage: " << prog << " [--iteration N] [flags]\n"
        "HELUT / CodedHELUT (Kim, Park, Lee, Cheon — ICML 2024).\n"
        "\n"
        "Look-up tables:\n"
        "  --lutsynth          Synthetic-table LUT sweep over HELUT-LT / HELUT-CI /\n"
        "                      CodedHELUT / CodedHELUT+p1 at (m=2, k=8 → 64-entry table,\n"
        "                      output dim 16). Source: HELUT Table 1.\n"
        "\n"
        "Compressed embeddings:\n"
        "  --embedding         CodedHELUT (SIMD variant) sweep on GloVe 6B-50d,\n"
        "                      GloVe 42B-300d, GPT-2 768d for (k, m) ∈\n"
        "                      {(8,8),(16,8),(32,8),(64,8),(32,16)}. Source: HELUT Table 2.\n"
        "  --logreg            Encrypted logistic regression on top of CodedHELUT for\n"
        "                      GloVe 50d / 300d (no 768d). Source: HELUT App. E.2.\n"
        "\n"
        "Cross-paper:\n"
        "  --emball            Run --lutsynth + --embedding + --logreg, plus the\n"
        "                      underlying core EEF (HELUT App. E.3) and EIF baselines\n"
        "                      (HELUT App. E.4) so the whole HELUT result table can be\n"
        "                      reproduced in one invocation.\n"
        "\n"
        "Common options:\n"
        "  --iteration N       Repetitions per benchmark (default 8).\n"
        "  --help              Show this message.\n";
}

int main(int argc, char **argv) {
    usint iteration        = 8;
    bool  indicator        = false;
    bool  anotherindicator = false;
    bool  lutsynth         = false;
    bool  embedding        = false;
    bool  logregt          = false;
    bool  any              = true;

    while (true) {
        int option_index = 0;
        static struct option long_options[] = {
            {"iteration",  required_argument, 0, 'i' },
            {"lutsynth",   no_argument,       0, 'l' },
            {"embedding",  no_argument,       0, 'e' },
            {"logreg",     no_argument,       0, 'g' },
            {"emball",     no_argument,       0, 'x' },
            {"help",       no_argument,       0, '?' },
            {0, 0, 0, 0}
        };

        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'i': iteration = parseIteration(optarg); break;
            case 'l': lutsynth  = true; any = false; break;
            case 'e': embedding = true; any = false; break;
            case 'g': logregt   = true; any = false; break;
            case 'x':
                indicator = anotherindicator = lutsynth = embedding = logregt = true;
                any = false;
                break;
            case '?': usage(argv[0]); return 0;
            default:  break;
        }
    }

    if (any) {
        usage(argv[0]);
        return 0;
    }

    cout << "iteration set to " << iteration << endl;

    // ── HELUT App. E.3 — EIF / EEF parameter sweep (cross-paper, lives in core) ─
    if (indicator) {
        EEFTests(iteration, /*scaleModSize=*/35);
        EEFTests(iteration, /*scaleModSize=*/50);
    }

    // ── HELUT App. E.4 / §D.3.1 — EIF baselines comparison (cross-paper, lives in core) ─
    if (anotherindicator) {
        AnotherIndicatorTests(iteration);
    }

    // ── HELUT Table 1 — Synthetic-table LUT sweep ──────────────────────────────
    // LUTSynthTests(bound, numcode, outputdim, iter) runs HELUT-LT (full
    // 64-entry table) + HELUT-CI / CodedHELUT / CodedHELUT-p1 (the coded variants
    // at m=2, k=8).
    if (lutsynth) {
        LUTSynthTests(/*bound=*/8, /*numcode=*/2, /*outputdim=*/16, iteration);
    }

    // ── HELUT Table 2 — Compressed-embedding sweep ─────────────────────────────
    // EmbeddingSIMDTests sweeps the SIMD CodedHELUT over the 3 embedding dims
    // (50, 300, 768) × 5 codebook configs internally.
    if (embedding) {
        EmbeddingSIMDTests(iteration);
    }

    // ── HELUT App. E.2 — Encrypted logistic regression on CodedHELUT ──────────
    // Resumable: LogregTests skips configs that already have results in
    // `logreg_result.txt` (so you can stop and restart without redoing work).
    if (logregt) {
        LogregTests(iteration);
    }

    cout << "All experiments are done." << endl;
    return 0;
}
