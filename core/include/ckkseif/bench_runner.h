#ifndef CKKSEIF_BENCH_RUNNER_H
#define CKKSEIF_BENCH_RUNNER_H

// Shared plumbing for benchmark / experiment code in `*Test` functions and
// every `main_*.cpp` dispatcher. Consolidates:
//   • CLI iteration parsing
//   • CKKS context + key generation boilerplate
//   • Benchmark header banner
//   • Synthetic input generators
//   • Precision / accuracy diagnostics
//   • CKKS bootstrap parameter helpers
//   • Result-logging helpers
// See docs/exp_convention.md for the target shape of a benchmark function.
//
// Only functions used by tests/exp/ live here. Library-side helpers (used by
// core/src/ or modules/*/src/) stay in utils.h.

#include "openfhe.h"
#include "utils.h"

#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace ckkseif {

//----------------------------------------------------------------------------
//   CLI helpers
//----------------------------------------------------------------------------

// Parse `--iteration N`. Replaces the legacy `(usint)*optarg - 48` trick that
// silently truncated multi-digit values (e.g. "16" → 1).
inline usint parseIteration(const char *optarg, usint fallback = 8) {
    if (!optarg || !*optarg) return fallback;
    int v = std::atoi(optarg);
    return v > 0 ? static_cast<usint>(v) : fallback;
}

//----------------------------------------------------------------------------
//   CKKS context + key generation
//----------------------------------------------------------------------------

enum class CKKSFeature {
    PKE,
    KEYSWITCH,
    LEVELEDSHE,
    ADVANCEDSHE,
    FHE,
};

struct CKKSContext {
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly>  cc;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly>        keys;
};

// Diagnostic print of the finalized CKKS context (mod chain depth, ring dim,
// security level). Declared early because `makeCKKSContext` (inline) calls it.
void paramcheck(const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc);

// Build a CKKS context + key pair from the parameters every benchmark uses.
// `features` defaults to PKE+KEYSWITCH+LEVELEDSHE; callers that need
// ADVANCEDSHE / FHE pass them explicitly. Non-empty `rotIndices` triggers
// EvalRotateKeyGen.
inline CKKSContext makeCKKSContext(
        uint32_t multDepth,
        uint32_t scaleModSize,
        uint32_t batchSize = 1u << 16,
        std::initializer_list<CKKSFeature> features =
            {CKKSFeature::PKE, CKKSFeature::KEYSWITCH, CKKSFeature::LEVELEDSHE},
        const std::vector<int32_t> &rotIndices = {}) {

    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetRingDim(batchSize << 1);
    parameters.SetBatchSize(batchSize);

    auto cc = lbcrypto::GenCryptoContext(parameters);
    for (auto f : features) {
        switch (f) {
            case CKKSFeature::PKE:         cc->Enable(lbcrypto::PKE);         break;
            case CKKSFeature::KEYSWITCH:   cc->Enable(lbcrypto::KEYSWITCH);   break;
            case CKKSFeature::LEVELEDSHE:  cc->Enable(lbcrypto::LEVELEDSHE);  break;
            case CKKSFeature::ADVANCEDSHE: cc->Enable(lbcrypto::ADVANCEDSHE); break;
            case CKKSFeature::FHE:         cc->Enable(lbcrypto::FHE);         break;
        }
    }
    paramcheck(cc);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    if (!rotIndices.empty()) {
        cc->EvalRotateKeyGen(keys.secretKey, rotIndices);
    }

    return CKKSContext{cc, keys};
}

// Configure CCParams / CryptoContext for bootstrapping. bootSet1 sets the
// scaling-technique / secret-key-distribution knobs; bootSet2 enables FHE,
// generates bootstrap keys, and runs EvalBootstrapSetup.
void bootSet1(lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> parameters, const usint scaleModSize);
void bootSet2(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc, const lbcrypto::PrivateKey<lbcrypto::DCRTPoly> privateKey, const usint batchSize);

//----------------------------------------------------------------------------
//   Timing-stat formatter
//----------------------------------------------------------------------------

// Print average + std of a per-iteration timing vector and return the same
// summary as a string (for logging into result files). Used by every *Test.
std::string statTime(const std::vector<double> times, const usint iteration);

//----------------------------------------------------------------------------
//   Benchmark header banner
//----------------------------------------------------------------------------

// `=== Name | k=v, k=v ===` per docs/exp_convention.md §4. Use at the very top
// of section 1 of every benchmark function.
inline void printBenchHeader(
        const std::string &name,
        std::initializer_list<std::pair<const char *, std::string>> params) {
    std::cout << "=== " << name;
    bool first = true;
    for (const auto &p : params) {
        std::cout << (first ? " | " : ", ") << p.first << "=" << p.second;
        first = false;
    }
    std::cout << " ===" << std::endl;
}

//----------------------------------------------------------------------------
//   Synthetic input generators
//----------------------------------------------------------------------------

std::vector<double> randomRealArray(const usint size, const double bound = 1.0);
std::vector<double> randomIntArray(const usint size, const usint bound);
std::vector<double> randomIntArrayNoised(const usint size, const usint bound, const usint noiselevel);
std::vector<usint>  fixedIntArray(const usint size, const usint bound);
std::vector<double> randomForRound(const usint size, const usint bound, const usint precision);
std::vector<double> randomDiscreteArray(const usint size, const usint bound);
std::vector<double> fixedDiscreteArray(const usint size, const usint bound);
std::vector<double> randomDiscreteArrayHalf(const usint size, const usint bound);
std::vector<double> fixedDiscreteArrayHalf(const usint size, const usint bound);
std::vector<double> fixedUBDiscreteArray(const usint size, const usint bound, const usint batchSize);
std::vector<double> equalvalueArray(const usint size, const usint bound, const usint batchSize);

//----------------------------------------------------------------------------
//   Precision / accuracy diagnostics
//----------------------------------------------------------------------------

usint  precisionMute(const lbcrypto::Plaintext vals, const std::vector<double> vals2, const usint size, const usint interval);
void   compprecision(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext, const std::vector<double> vals2, const usint size, const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc, const lbcrypto::KeyPair<lbcrypto::DCRTPoly> keys);
void   binaryprecision(const lbcrypto::Plaintext vals, const usint size);
double countprecisionMute(const lbcrypto::Plaintext vals, const std::vector<double> vals2, const usint size, const double resultnum, const bool show = false);
double countSIMDprecisionMute(const lbcrypto::Plaintext vals, const std::vector<double> vals2, const usint size, const double resultnum, const bool show = false);
double codedcountprecisionMute(const lbcrypto::Plaintext vals, const std::vector<double> vals2, const usint size, const double resultnum, const bool show = false);
void   roundprecision(const std::vector<double> vals1, const std::vector<double> vals2, const usint size);

//----------------------------------------------------------------------------
//   Result-logging helpers
//----------------------------------------------------------------------------

usint checkline(const std::string path);
void  addRes(std::vector<std::string> newline, std::string path, usint iteration);

}

#endif
