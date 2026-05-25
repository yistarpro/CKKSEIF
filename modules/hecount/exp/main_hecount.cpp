#define PROFILE

#include "openfhe.h"
#include "test_count.h"
#include "bench_runner.h"

#include <iostream>
#include <getopt.h>
#include <cmath>

using namespace lbcrypto;
using namespace std;
using namespace ckkseif;

static void usage(const char *prog) {
    cerr <<
        "Usage: " << prog << " [--iteration N] [flags]\n"
        "HECount — Counting / TF-IDF / IR pipeline (Kim, Yun, Cheon, Park — ICISC 2024).\n"
        "\n"
        "Counting:\n"
        "  --count             NaiveCount (Alg 1) + CodedCount (Alg 2 / Alg 5 with\n"
        "                      BasisExp exponentBound=1 and =4) at size=256, base=2,\n"
        "                      dim=8. Source: HECount Table 2.\n"
        "  --paralcount        ParalCount (Alg 7) at sizes 256 / 4096 / 16384,\n"
        "                      base=2, dim=8. Source: HECount Table 3.\n"
        "\n"
        "n-gram extraction:\n"
        "  --ngram             2-gram and 3-gram extraction at base=2 with two\n"
        "                      `dim` regimes (4 and 6). Source: HECount Table 4 /\n"
        "                      §4.2 Fig. 2.\n"
        "\n"
        "Information retrieval (Amazon Fine Food Reviews):\n"
        "  --info              One CodedCountSIMD warmup (size=256) followed by\n"
        "                      InfoRetrievalAfterTF at sizes 256 / 512 / 1024 against\n"
        "                      vocab=1024. Source: HECount Table 5 / §4.3.\n"
        "\n"
        "  --countall          Run --count + --paralcount + --ngram + --info in one\n"
        "                      invocation.\n"
        "\n"
        "Common options:\n"
        "  --iteration N       Repetitions per benchmark (default 8).\n"
        "  --help              Show this message.\n";
}

int main(int argc, char **argv) {
    usint iteration  = 8;
    bool  count      = false;
    bool  ngram      = false;
    bool  info       = false;
    bool  paralcount = false;
    bool  any        = true;

    while (true) {
        int option_index = 0;
        static struct option long_options[] = {
            {"iteration",  required_argument, 0, 'i' },
            {"count",      no_argument,       0, 't' },
            {"ngram",      no_argument,       0, 'm' },
            {"info",       no_argument,       0, 'o' },
            {"paralcount", no_argument,       0, 'c' },
            {"countall",   no_argument,       0, 'b' },
            {"help",       no_argument,       0, '?' },
            {0, 0, 0, 0}
        };

        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'i': iteration  = parseIteration(optarg); break;
            case 't': count      = true; any = false; break;
            case 'm': ngram      = true; any = false; break;
            case 'o': info       = true; any = false; break;
            case 'c': paralcount = true; any = false; break;
            case 'b':
                count = ngram = info = paralcount = true;
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

    // ── HECount Table 2 — NaiveCount + CodedCount ─────────────────────────
    // Same input regime (size=256, base=2, dim=8 → bound=256). NaiveCount is
    // the baseline; CodedCount runs at exponentBound=1 (no BasisExp) and 4.
    if (count) {
        const usint base    = 2;
        const usint dim     = 8;
        const usint rotsize = 256;     // 0 ⇒ full-slot mode
        NaiveCountTest(/*scaleMod=*/50, /*bound=*/(usint) pow(base, dim), rotsize, iteration);
        CodedCountTest(/*scaleMod=*/50, base, dim, rotsize, /*exponentBound=*/1, iteration);
        CodedCountTest(/*scaleMod=*/50, base, dim, rotsize, /*exponentBound=*/4, iteration);
    }

    // ── HECount Table 4 / §4.2 — n-gram extraction ─────────────────────────
    if (ngram) {
        const usint rotsize = 256;
        // (n, dim, partialRatio): paper sweeps both 2-gram and 3-gram at
        // dim=4 (no partial), then dim=6 with three partial-bound settings.
        NgramTest(50, /*base=*/2, /*dim=*/4, rotsize, /*exponentBound=*/4, /*n=*/2, /*ratio%=*/0,   iteration);
        NgramTest(50, /*base=*/2, /*dim=*/4, rotsize, /*exponentBound=*/4, /*n=*/3, /*ratio%=*/0,   iteration);
        NgramTest(50, /*base=*/2, /*dim=*/6, rotsize, /*exponentBound=*/6, /*n=*/2, /*ratio%=*/10,  iteration);
        NgramTest(50, /*base=*/2, /*dim=*/6, rotsize, /*exponentBound=*/6, /*n=*/2, /*ratio%=*/50,  iteration);
        NgramTest(50, /*base=*/2, /*dim=*/6, rotsize, /*exponentBound=*/6, /*n=*/3, /*ratio%=*/0.1, iteration);
    }

    // ── HECount Table 3 — Parallelized Coded Counting (ParalCount) ─────────
    if (paralcount) {
        const usint scaleMod = 50;
        CodedCountSIMDTest(scaleMod, /*base=*/2, /*dim=*/8, /*size=*/256,   /*maxlen=*/256, iteration);
        CodedCountSIMDTest(scaleMod, /*base=*/2, /*dim=*/8, /*size=*/4096,  /*maxlen=*/256, iteration);
        CodedCountSIMDTest(scaleMod, /*base=*/2, /*dim=*/8, /*size=*/16384, /*maxlen=*/256, iteration);
    }

    // ── HECount Table 5 / §4.3 — Information retrieval on Amazon Fine Food Reviews ──
    // Warmup with one ParalCount (dim=10 → vocab=1024) so any first-call setup
    // amortizes, then run IR with precomputed TF at three document sizes.
    if (info) {
        const usint scaleMod = 50;
        CodedCountSIMDTest      (scaleMod, /*base=*/2, /*dim=*/10, /*size=*/256, /*maxlen=*/256,  iteration);
        InfoRetrievalAfterTFTest(scaleMod, /*size=*/256,  /*vocabsize=*/1024, iteration);
        InfoRetrievalAfterTFTest(scaleMod, /*size=*/512,  /*vocabsize=*/1024, iteration);
        InfoRetrievalAfterTFTest(scaleMod, /*size=*/1024, /*vocabsize=*/1024, iteration);
    }

    cout << "All experiments are done." << endl;
    return 0;
}
