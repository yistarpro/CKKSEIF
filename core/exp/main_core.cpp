#define PROFILE

#include "openfhe.h"
#include "test_core.h"
#include "bench_runner.h"

#include <iostream>
#include <getopt.h>

using namespace lbcrypto;
using namespace std;
using namespace ckkseif;

static void usage(const char *prog) {
    cerr <<
        "Usage: " << prog << " [--iteration N] [flags]\n"
        "Core EIF / EEF / ESF benchmarks shared by the HELUT, HECount, and PrivTopk papers.\n"
        "\n"
        "Indicator / EEF (HELUT):\n"
        "  --indicator         EEF (Encrypted Indicator Function) sweep over log p\n"
        "                      at log Δ = 35 and 50. Source: HELUT App. E.3.\n"
        "  --anotherindicator  EIF baselines: Lagrange interpolation, Cheon et al.\n"
        "                      comparison-based, Lee et al. (HEaaN-Stat) sinc-based.\n"
        "                      Source: HELUT App. E.4 / §D.3.1.\n"
        "\n"
        "Sign Function (PrivTopk):\n"
        "  --esf               Encrypted Sign Function (ESF) precision sweep at\n"
        "                      log Δ = 50, message bound = 64. Source: PrivTopk §II-B.\n"
        "  --esfq              Quantized arbitrary-precision ESF at log Δ = 49 for\n"
        "                      32-bit and 16-bit total precision (4-bit segments).\n"
        "                      Source: PrivTopk §II-B / §V-B2.\n"
        "\n"
        "Shared infrastructure (not paper-attributed):\n"
        "  --boot              CKKS bootstrap micro-benchmark — runs the sparse-ternary\n"
        "                      `bootTest` configuration and the OpenFHE-template\n"
        "                      `bootTest2` configuration in sequence.\n"
        "  --log               `EvalLog` micro-benchmark at bound=2.0, degree=10.\n"
        "\n"
        "Common options:\n"
        "  --iteration N       Repetitions per benchmark (default 8).\n"
        "  --help              Show this message.\n";
}

int main(int argc, char **argv) {
    usint iteration        = 8;
    bool  indicator        = false;
    bool  anotherindicator = false;
    bool  esf              = false;
    bool  esfq             = false;
    bool  boot             = false;
    bool  logbench         = false;
    bool  any              = true;

    while (true) {
        int option_index = 0;
        static struct option long_options[] = {
            {"iteration",        required_argument, 0, 'i' },
            {"indicator",        no_argument,       0, 's' },
            {"anotherindicator", no_argument,       0, 'a' },
            {"esf",              no_argument,       0, 'p' },
            {"esfq",             no_argument,       0, 'q' },
            {"boot",             no_argument,       0, 'b' },
            {"log",              no_argument,       0, 'l' },
            {"help",             no_argument,       0, '?' },
            {0, 0, 0, 0}
        };

        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'i': iteration        = parseIteration(optarg); break;
            case 's': indicator        = true; any = false; break;
            case 'a': anotherindicator = true; any = false; break;
            case 'p': esf              = true; any = false; break;
            case 'q': esfq             = true; any = false; break;
            case 'b': boot             = true; any = false; break;
            case 'l': logbench         = true; any = false; break;
            case '?': usage(argv[0]); return 0;
            default:  break;
        }
    }

    if (any) {
        usage(argv[0]);
        return 0;
    }

    cout << "iteration set to " << iteration << endl;

    // ── HELUT App. E.3 — EIF / EEF parameter sweep ───────────────────────────
    if (indicator) {
        EEFTests(iteration, /*scaleModSize=*/35);
        EEFTests(iteration, /*scaleModSize=*/50);
    }

    // ── HELUT App. E.4 / §D.3.1 — EIF baselines comparison ───────────────────
    if (anotherindicator) {
        AnotherIndicatorTests(iteration);
    }

    // ── HELUT App. E.4 — Encrypted Sign Function ─────────────────────────────
    if (esf) {
        ESFTests(/*scaleModSize=*/50, /*bound=*/64);
    }

    // ── PrivTopk §II-B / §V-B2 — Quantized ESF ───────────────────────────────
    //   (49, 32, 4) → 8 segments of 4 bits each (32-bit precision overall).
    //   (49, 16, 4) → 4 segments of 4 bits each (16-bit precision overall).
    if (esfq) {
        ESFQTest(/*scaleModSize=*/49, /*boundBits=*/32, /*baseBits=*/4);
        ESFQTest(/*scaleModSize=*/49, /*boundBits=*/16, /*baseBits=*/4);
    }

    // ── Shared infrastructure — CKKS bootstrap micro-benchmarks ──────────────
    // bootTest runs at the sparse-ternary regime PrivTopk uses; bootTest2 is the
    // OpenFHE example-style configuration kept as a cross-check.
    if (boot) {
        bootTest(/*scaleModSize=*/45, /*logbatchSize=*/16, /*levelBudgetElmt=*/4, iteration, /*precparam=*/0);
        bootTest2();
    }

    // ── Shared infrastructure — EvalLog micro-benchmark ──────────────────────
    if (logbench) {
        logTest(/*bound=*/2.0, /*degree=*/10, iteration, /*scaleModSize=*/35);
    }

    cout << "All experiments are done." << endl;
    return 0;
}
