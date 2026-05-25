#define PROFILE

#include "openfhe.h"
#include "test_parity.h"

#include <iostream>
#include <getopt.h>

using namespace lbcrypto;
using namespace std;
using namespace ckkseif;

static void usage(const char *prog) {
    cerr <<
        "Usage: " << prog << " [flags]\n"
        "Parity / bit-decomposition playground (modules/parity/).\n"
        "Not associated with any of the three papers — this module is a sandbox\n"
        "for parity (ParityBySin) and bit-decomposition (ExtractMSBs / ExtractLSBs /\n"
        "DecompToBits) primitives. Both tests are single-shot smoke tests.\n"
        "\n"
        "  --parity            ParityBySin smoke test. Domain Z_{2^d} for d=8,\n"
        "                      Chebyshev order K=8, log Δ = 35.\n"
        "  --bd                Bit-decomposition smoke test (ExtractLSBs). Bound=256,\n"
        "                      log Δ = 50. The `iter` arg is a forwarded bit-count\n"
        "                      parameter used by the ExtractMSBs swap (see the body).\n"
        "  --help              Show this message.\n";
}

int main(int argc, char **argv) {
    bool parity = false;
    bool bd     = false;
    bool any    = true;

    while (true) {
        int option_index = 0;
        static struct option long_options[] = {
            {"parity", no_argument, 0, 'p' },
            {"bd",     no_argument, 0, 'b' },
            {"help",   no_argument, 0, '?' },
            {0, 0, 0, 0}
        };

        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'p': parity = true; any = false; break;
            case 'b': bd     = true; any = false; break;
            case '?': usage(argv[0]); return 0;
            default:  break;
        }
    }

    if (any) {
        usage(argv[0]);
        return 0;
    }

    // ── ParityBySin smoke test ────────────────────────────────────────────
    if (parity) {
        ParityTest(/*d=*/8, /*K=*/8, /*scaleModSize=*/35);
    }

    // ── ExtractLSBs / bit-decomposition smoke test ────────────────────────
    if (bd) {
        BDtest(/*scaleModSize=*/50, /*bound=*/256, /*iter=*/8);
    }

    cout << "All experiments are done." << endl;
    return 0;
}
