#include "openfhe.h"
#include "utils.h"
#include "eif.h"
#include "arithmetic.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <map>
#include <omp.h>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

// HELUT §3.1 / Alg 1 — paramSq: build Lagrange polynomial whose roots are
// {1/bound, 2/bound, …, (bound-1)/bound}, expanded via Horner.
// Returned coefficients are unnormalized; consumers (IndicatorByLagrange)
// divide by coeff[0] to normalize.
vector<double> ParamSqMethod(const usint bound){
    vector<double> coeff(bound, 0.0);
    coeff[0] = 1;
    for (usint i = 1; i < bound; i++) {
        for (usint j = i; j != 0; j--) {
            coeff[j] = coeff[j - 1] - coeff[j] * ((double) i / (double) bound);
        }
        coeff[0] *= -((double) i / (double) bound);
    }
    return coeff;
}



// HELUT §3 — indicator-checker plaintext generator (single target value).
Plaintext GenEEFChecker(const usint bound, const CryptoContext<DCRTPoly> cc){
    int32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    std::vector<double> num(bound);
    for(usint i=0 ; i < bound; i ++){
        num[i]=i;
    }

    std::vector<double> nums(batchSize);
    nums = fullCopy(num, batchSize, bound);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(nums);
    return ptxt;
}


// HELUT §3 — indicator-checker plaintext generator (range [from, from+size)).
Plaintext GenEEFCheckerInterval(const usint from, const usint size, const CryptoContext<DCRTPoly> cc){
    int32_t batchSize = cc->GetEncodingParams()->GetBatchSize();

    std::vector<double> num(batchSize/size);
    for(usint i=0 ; i < batchSize/size; i ++){
        num[i]=from+i;
    }

    std::vector<double> nums(batchSize);
    nums = repeat(num, batchSize, size);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(nums);
    return ptxt;
}



// HELUT §3 — recursive variant of GenEEFCheckerInterval, for hierarchical target sets.
Plaintext GenEEFCheckerIntervalRecursive(const usint from, const usint to, const usint size, const CryptoContext<DCRTPoly> cc){
    int32_t batchSize = cc->GetEncodingParams()->GetBatchSize();

    std::vector<double> num(to-from);
    for(usint i=0 ; i < to-from; i ++){
        num[i]=from+i;
    }

    std::vector<double> nums(batchSize/size);
    nums = fullCopy(num, batchSize/size, to-from);

    std::vector<double> numss(batchSize);
    numss = repeat(nums, batchSize, size);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(numss);
    return ptxt;
}

// Multi-version included

// HELUT §3 — indicator-checker for a partial-array (subset) target list.
// Slot k gets `list[from + k]` for k ∈ [0, batchSize/size). Pads with the last
// available list entry if the request exceeds list bounds (defensive against
// caller miscalculations of `from`).
Plaintext GenEEFCheckerPartialArray(const usint from, const usint size, const CryptoContext<DCRTPoly> cc, const vector<usint> list){
    int32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    const usint slots = batchSize / size;

    std::vector<double> num(slots);
    for(usint i = 0; i < slots; i++){
        usint idx = from + i;
        num[i] = (idx < list.size()) ? list[idx] : list.back();
    }

    std::vector<double> nums = repeat(num, batchSize, size);
    return cc->MakeCKKSPackedPlaintext(nums);
}



// HELUT §3.3 / Alg 2 — paramInd: select (r, s) for the full EIF.
//   rounds[0] = r (SqMethod squaring rounds);
//   rounds[1] = s (Cleanse iterations).
//
// Structure: a closed-form base depending on `boundbits = log2(bound)`, plus
// hand-tuned offsets per `scaleModSize` tier. The offsets are the author's
// empirical adjustments to hit the precision target at each (boundbits, scaleModSize)
// cell; preserved verbatim. Add a clause when introducing a new scaleModSize regime.
vector<usint> ParamEEF(const usint bound, const usint scaleModSize) {
    const usint boundbits = log2(bound);

    // Binary case is degenerate: SqMethod is skipped (EEFBinary path).
    if (boundbits == 1) {
        const usint s = (scaleModSize >= 59) ? 2 : 1;
        return {0, s};
    }

    // Base parameters (apply at any scaleModSize).
    int r = 2 + 2 * boundbits
          - (boundbits >= 5 ? 1 : 0)
          - (boundbits >= 7 ? 1 : 0);
    int s = 1
          + (boundbits >= 4 ? 1 : 0)
          + (boundbits >= 6 ? 1 : 0);

    // Per-tier offsets. Each block is purely additive on (r, s).
    if (scaleModSize >= 40) {
        r += 1;
        if (boundbits <= 4) r -= 1;
        if (boundbits == 7) r += 1;
    }
    if (scaleModSize >= 45) {
        if (boundbits <= 4)                                        r += 1;
        if (boundbits == 7 || boundbits == 9)                      r += 1;
        if (boundbits == 6 || boundbits == 7 || boundbits == 9)    s -= 1;
    }
    if (scaleModSize >= 50) {
        if (boundbits >= 7)                                        r += 1;
        if (boundbits == 9  || boundbits == 13)                    r -= 1;
        if (boundbits == 7) {                                      r -= 2;  s += 1; }
        if (boundbits == 4)                                        s -= 1;
        if (boundbits >= 7)                                        s -= 1;
        if (boundbits == 9  || boundbits >= 12)                    s += 1;
    }
    if (scaleModSize >= 55) {
        if (boundbits >= 5 && boundbits <= 8) { r += 1;  s -= 1; }
        if (boundbits >= 13)                  { r += 1; }
        if (boundbits >= 12)                  { s -= 1; }
    }
    if (scaleModSize >= 59) {
        if (boundbits == 9) { r += 1;  s -= 1; }
    }

    return {static_cast<usint>(r), static_cast<usint>(s)};
}



// HELUT §3 — paramZeroTest counterpart of ParamEEF for the ZeroTest primitive.
// Same shape as ParamEEF (hand-tuned per (boundbits, scaleModSize)); the
// numbers differ because ZeroTest skips one squaring level relative to EEF.
//   rounds[0] = r (SqMethod squaring rounds);
//   rounds[1] = s (Cleanse iterations).
vector<usint> ParamZeroTest(const usint bound, const usint scaleModSize) {
    const usint boundbits = log2(bound);

    // Binary case is degenerate.
    if (boundbits == 1) return {0, 0};

    // Base parameters (apply at any scaleModSize).
    int r = 2 + boundbits;
    int s = 1 + (boundbits >= 4 ? 1 : 0);

    // Per-tier offsets. Each block is purely additive on (r, s).
    if (scaleModSize >= 40) {
        r += 1;
        if (boundbits == 4 || boundbits == 5)                      s -= 1;
    }
    if (scaleModSize >= 45) {
        if (boundbits == 6 || boundbits == 7)                      s -= 1;
    }
    if (scaleModSize >= 50) {
        if (boundbits >= 3)                                        r += 1;
        if (boundbits >= 7)                                        r -= 1;
        if (boundbits == 8 || boundbits == 9 || boundbits == 10)   s -= 1;
    }
    if (scaleModSize >= 59) {
        if (boundbits == 2)                                        r += 1;
        if (boundbits >= 7)                                        r += 1;
        if (boundbits >= 11)                                       s -= 1;
    }

    return {static_cast<usint>(r), static_cast<usint>(s)};
}


// HELUT §3.2 / Thm 3.2 / Eq. 12-13 — Cleanse(x) = 3x² - 2x³ rounding step.
// Maps x ∈ [0, 1] toward {0, 1}: each iteration is a contraction toward the
// fixed points {0, 1}. `round` iterations compound the rounding.
Ciphertext<DCRTPoly> Cleanse(Ciphertext<DCRTPoly> ciphertext, const usint round) {
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = ciphertext->Clone();

    for (usint i = 0; i < round; i++) {
        Ciphertext<DCRTPoly> power  = cc->EvalSquare(result);          // x²
        cc->ModReduceInPlace(power);
        Ciphertext<DCRTPoly> power2 = cc->EvalAdd(power, power);       // 2x²
        result = cc->EvalMult(result, power2);                          // x · 2x² = 2x³
        cc->ModReduceInPlace(result);
        cc->EvalAddInPlace(power, power2);                              // x² + 2x² = 3x²
        result = cc->EvalSub(power, result);                            // 3x² - 2x³
    }
    return result;
}


// HELUT §3.3 / Eq. 7 — EEF = Cleanse^{(s)} ∘ SqMethod_{r,p}^a (the proposed EIF).
// rounds[0] = r (squaring rounds in SqMethod); rounds[1] = s (Cleanse iterations).
Ciphertext<DCRTPoly> EEF(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const double numtocheck){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    const double div = 1.0 / (double) bound;

    Ciphertext<DCRTPoly> result;
    if (bound > 2) {
        // SqMethod step: result = 2 * ((x - target) / bound)^2 - 1
        result = cc->EvalSub(ciphertext, numtocheck);
        cc->EvalMultInPlace(result, div);
        cc->ModReduceInPlace(result);
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
        cc->EvalAddInPlace(result, result);
        cc->EvalAddInPlace(result, -1);
    }
    if (bound == 2 && numtocheck == 1) result = ciphertext->Clone();
    if (bound == 2 && numtocheck == 0) {
        // 1 - x: maps x=0 → 1, x=1 → 0.
        result = cc->EvalAdd(ciphertext, -1);
        cc->EvalNegateInPlace(result);
    }

    // r squaring rounds: amplify |result| < 1 → 0, |result| = 1 → 1.
    for (usint i = 0; i < rounds[0]; i++) {
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
    }

    // s Cleanse iterations: round each slot toward 0 or 1.
    for (usint i = 0; i < rounds[1]; i++) {
        Ciphertext<DCRTPoly> power  = cc->EvalSquare(result);
        cc->ModReduceInPlace(power);
        Ciphertext<DCRTPoly> power2 = cc->EvalAdd(power, power);
        result = cc->EvalMult(result, power2);
        cc->ModReduceInPlace(result);
        cc->EvalAddInPlace(power, power2);
        result = cc->EvalSub(power, result);
    }

    return result;
}


// HELUT §3 — EEF specialized to p=2 (binary domain).
// result = -(x² - 1) = 1 - x². For x ∈ {0, 1}: maps 0 → 1 (hit), 1 → 0 (miss).
Ciphertext<DCRTPoly> EEFBinary(const Ciphertext<DCRTPoly> ciphertext, const vector<usint> rounds){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

    Ciphertext<DCRTPoly> result = cc->EvalSquare(ciphertext);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, -1);
    cc->EvalNegateInPlace(result);

    for (usint i = 0; i < rounds[0]; i++) {
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
    }
    for (usint i = 0; i < rounds[1]; i++) {
        Ciphertext<DCRTPoly> power  = cc->EvalSquare(result);
        cc->ModReduceInPlace(power);
        Ciphertext<DCRTPoly> power2 = cc->EvalAdd(power, power);
        result = cc->EvalMult(result, power2);
        cc->ModReduceInPlace(result);
        cc->EvalAddInPlace(power, power2);
        result = cc->EvalSub(power, result);
    }

    return result;
}



// HELUT §3 — ZeroTest: detect x=0 from x ∈ [0, bound). Skips EEF's initial
// squaring step, instead starts from `2x/bound - 1` directly. This is cheaper
// (saves one level) but works only when the answer is known to be the
// "x=0 ↔ result=1" form (no other target value). Uses ParamZeroTest for r, s.
Ciphertext<DCRTPoly> ZeroTest(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    const double div = 1.0 / (double) bound;

    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    if (bound != 1.0) {
        result = cc->EvalMult(result, div);
        cc->ModReduceInPlace(result);
    }
    cc->EvalAddInPlace(result, result);
    cc->EvalAddInPlace(result, -1);     // result = 2x/bound - 1

    for (usint i = 0; i < rounds[0]; i++) {
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
    }
    for (usint i = 0; i < rounds[1]; i++) {
        Ciphertext<DCRTPoly> power  = cc->EvalSquare(result);
        cc->ModReduceInPlace(power);
        Ciphertext<DCRTPoly> power2 = cc->EvalAdd(power, power);
        result = cc->EvalMult(result, power2);
        cc->ModReduceInPlace(result);
        cc->EvalAddInPlace(power, power2);
        result = cc->EvalSub(power, result);
    }

    return result;
}


// HELUT §3 — EEF SIMD-parallel variant (per-slot target via Plaintext mask).
// `levlimit` triggers in-loop EvalBootstrap when the running ciphertext level
// exceeds it (set to a depth-budget threshold; default 100 ≈ never-bootstrap).
Ciphertext<DCRTPoly> EEFSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const Plaintext numtocheck, const usint levlimit){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    const double div = 1.0 / (double) bound;

    Ciphertext<DCRTPoly> result;

    if (bound > 2) {
        result = cc->EvalSub(ciphertext, numtocheck);
        cc->EvalMultInPlace(result, div);
        cc->ModReduceInPlace(result);
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
        cc->EvalAddInPlace(result, result);
        cc->EvalAddInPlace(result, -1);
    }

    if (bound == 2) {
        // Per-slot: if target=1, compute x (identity); if target=0, compute 1-x.
        // Build (mult, add) plaintext masks so EvalMult+EvalAdd applies both at
        // once: result = x*mult + add where (mult, add) ∈ {(1, 0), (-1, 1)}.
        vector<double> checker     = numtocheck->GetRealPackedValue();
        vector<double> checkerAdd (checker.size());
        vector<double> checkerMult(checker.size());
        for (usint i = 0; i < checker.size(); i++) {
            if (checker[i] > 0.5) { checkerAdd[i] = 0.0; checkerMult[i] =  1.0; }
            else                  { checkerAdd[i] = 1.0; checkerMult[i] = -1.0; }
        }
        Plaintext ptxtAdd  = cc->MakeCKKSPackedPlaintext(checkerAdd);
        Plaintext ptxtMult = cc->MakeCKKSPackedPlaintext(checkerMult);
        result = cc->EvalMult(ciphertext, ptxtMult);
        result = cc->EvalAdd(result, ptxtAdd);
    }

    for (usint i = 0; i < rounds[0]; i++) {
        if (levlimit < (result->GetLevel())) result = cc->EvalBootstrap(result, 2, 10);
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
    }
    for (usint i = 0; i < rounds[1]; i++) {
        if (levlimit < (result->GetLevel())) result = cc->EvalBootstrap(result, 2, 10);
        Ciphertext<DCRTPoly> power  = cc->EvalSquare(result);
        cc->ModReduceInPlace(power);
        Ciphertext<DCRTPoly> power2 = cc->EvalAdd(power, power);
        result = cc->EvalMult(result, power2);
        cc->ModReduceInPlace(result);
        cc->EvalAddInPlace(power, power2);
        result = cc->EvalSub(power, result);
    }

    return result;
}




//----------------------------------------------------------------------------------
//   Comparison
//----------------------------------------------------------------------------------


// Shared utility — rotation keys for embedding-style ciphertext packing.
// Generates rotation indices {mk/2, mk/4, …, 1} for log₂(mk) levels of
// halving. Used by HELUT (CodedHELUT_P1) and HECount (Count) when packing
// codebook segments into a single ciphertext at stride `mk`.
void AddRotKeyForEmb(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t mk){
    int32_t copy = mk;
    const long levels = log2(mk);
    std::vector<int32_t> arr(levels);
    for (long i = 0; i < levels; i++) {
        copy >>= 1;
        arr[i] = copy;
    }
    cc->EvalRotateKeyGen(privateKey, arr);
}


//----------------------------------------------------------------------------------
//   Alternative EEF (HELUT §D.3.1)
//----------------------------------------------------------------------------------
	

// HELUT §D.3.1 — alternative EIF using Sinc approximation (Lee et al.,
// HEaaN-Stat 2023 baseline). Approximates the indicator via
// sinc(πx) · cos(πx) iterated through doubling-angle for d levels, then
// applies a final cubic polynomial as a Cleanse-equivalent.
Ciphertext<DCRTPoly> IndicatorBySinc(const Ciphertext<DCRTPoly> ciphertext, const usint d, const usint K){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    const double bound = (double)(1 << d);
    const double div   = 1.0 / bound;

    Ciphertext<DCRTPoly> norm = cc->EvalMult(ciphertext, div);
    cc->ModReduceInPlace(norm);
    Ciphertext<DCRTPoly> coscipher  = cc->EvalChebyshevFunction(
        [](double x) -> double { return std::cos(x * M_PI); }, norm, -1, 1, K);
    Ciphertext<DCRTPoly> sinccipher = cc->EvalChebyshevFunction(
        [](double x) -> double { return (x != 0) ? std::sin(M_PI * x) / (M_PI * x) : 1.0; }, norm, -1, 1, K);

    sinccipher = cc->EvalMult(sinccipher, coscipher);
    for (usint i = 1; i < d; i++) {
        cc->ModReduceInPlace(sinccipher);
        coscipher = cc->EvalMult(coscipher, coscipher);
        cc->ModReduceInPlace(coscipher);
        coscipher = cc->EvalAdd(coscipher, coscipher);
        coscipher = cc->EvalSub(coscipher, 1);
        sinccipher = cc->EvalMult(sinccipher, coscipher);
    }
    cc->ModReduceInPlace(sinccipher);

    // Final cubic: 4x³ - 3x² (the Cleanse-equivalent for sinc-based output).
    return cc->EvalPoly(sinccipher, {0, 0, 4, -3});
}




// HELUT §D.3.1 — alternative EIF via Lagrange interpolation (strawman baseline).
// Normalizes x → x/bound, evaluates the (bound-1)-degree Lagrange polynomial
// from ParamSqMethod, divides by coeff[0] to normalize, then one Cleanse.
Ciphertext<DCRTPoly> IndicatorByLagrange(Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<double> coeff) {
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

    Ciphertext<DCRTPoly> result = cc->EvalMult(ciphertext, 1.0 / (double) bound);
    cc->ModReduceInPlace(result);
    result = cc->EvalPoly(result, coeff);
    result = cc->EvalMult(result, 1.0 / (double) coeff[0]);
    cc->ModReduceInPlace(result);
    result = Cleanse(result, 1);

    return result;
}


} // namespace ckkseif
