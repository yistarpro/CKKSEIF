#include "openfhe.h"
#include "utils.h"
#include "arithmetic.h"
#include "eif.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <map>
#include <omp.h>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

// Helper — rotation-index generator for RotSum (powers-of-two reduction).
// Returns {from/2, from/4, …, to}. Bidirectional appends the negatives.
std::vector<int32_t> GenIdxForRotsum(const int32_t from, const int32_t to, const bool bidirectional) {
    const int32_t round = log2(from / to);
    std::vector<int32_t> arr(bidirectional ? 2 * round : round);

    for (int32_t s = 1; s < round + 1; s++) {
        arr[s - 1] = from >> s;
        if (bidirectional) arr[round + s - 1] = -arr[s - 1];
    }
    return arr;
}


// Helper — rotation-index generator for evenly-spaced rotations.
// Returns {base, 2*base, …, number*base}. Bidirectional appends the negatives.
std::vector<int32_t> GenIdxForMultiples(const int32_t base, const int32_t number, const bool bidirectional) {
    std::vector<int32_t> arr(bidirectional ? 2 * number : number);

    for (int32_t s = 1; s < number + 1; s++) {
        arr[s - 1] = base * s;
        if (bidirectional) arr[number + s - 1] = -arr[s - 1];
    }
    return arr;
}




// Helper — generate rotation keys for all powers-of-two up to batchSize (bidirectional).
void AddRotKeyForPo2(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t batchSize){
    int32_t copy=batchSize;
    std::vector<int32_t> arr(2*log2(batchSize));
    for(long i = 0 ; i < log2(batchSize) ; i++){
        copy >>= 1;
        arr[i]=(copy);
        arr[log2(batchSize)+i]=-(copy);
    }
    cc->EvalRotateKeyGen(privateKey, arr);

}


// Helper — bootstrap with auto-selected level budget based on ciphertext state.
Ciphertext<DCRTPoly> BootAuto(Ciphertext<DCRTPoly> ciphertext){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    const auto cryptoParamsCKKS =
    std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
          cc->GetCryptoParameters());

	usint RingDim = log2(cc->GetRingDimension());
    usint levelBudgetElmt= (RingDim >15 ) ? 1 << (RingDim-14) : 2 ;
    std::vector<uint32_t> levelBudget = {levelBudgetElmt, levelBudgetElmt};

    Ciphertext<DCRTPoly> result;
    usint depth = FHECKKSRNS::GetBootstrapDepth(levelBudget, cryptoParamsCKKS->GetSecretKeyDist());
    usint current = ciphertext->GetLevel();
    if(depth >= current)
        result = ciphertext->Clone();
    else{
        result = cc->EvalBootstrap(ciphertext);
    }
    return result;
}


// Helper — binary-tree product of a vector of ciphertexts (log-depth multiplication).
Ciphertext<DCRTPoly> Product(const vector<Ciphertext<DCRTPoly>> ciphertext){
    usint num = ciphertext.size();
    usint phase = ceil(log2(num));
    usint res = 0;
    const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();

    vector<Ciphertext<DCRTPoly>> result(num);
    for(usint i=0; i<num ; i++){
        result[i] = ciphertext[i]->Clone();
    }
    for(usint i=0; i< phase; i++){
        res = num%2;
        num /=2;
        for(usint j=0; j< num; j++ ){
            result[j]=cc->EvalMult(result[2*j],result[2*j+1]);
            cc->ModReduceInPlace(result[j]);
        }
        if(res==1){
            result[num]=result[2*num]->Clone();
            num+=res;
        }
    }
    return result[0];
}




// Helper — polynomial-approximated logarithm, used by IDF in HECount.
// Computes log_base(x) via Taylor series of log(1+y) for y = x/bound - 1.
// Returns log_base(x/bound); caller adds log_base(bound) if absolute log needed.
Ciphertext<DCRTPoly> EvalLog(const Ciphertext<DCRTPoly> ciphertext, const double bound, const double base, const usint degree) {
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = cc->EvalMult(ciphertext, 1.0 / bound);
    cc->ModReduceInPlace(result);
    result = cc->EvalSub(result, 1);                      // y = x/bound - 1

    vector<double> coeff(degree + 1);
    double logbase = (base > 1) ? log2(base) : 1.0;
    double coeff0  = 1.0 / logbase;
    coeff[0] = 0;
    for (usint i = 1; i < degree + 1; i++) {
        coeff[i] = coeff0 / (double) i;
        coeff0   = -coeff0;
    }
    result = cc->EvalPoly(result, coeff);                  // ≈ log_base(1 + y)
    return result;
}



// Helper — log-like polynomial (degree-2 approximation, faster than EvalLog).
Ciphertext<DCRTPoly> EvalLogLike(const Ciphertext<DCRTPoly> ciphertext, const double bound){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = cc->EvalMult(ciphertext, 1/bound);
    cc->ModReduceInPlace(result);

    vector<double> coeff={0, 1, -0.5};
    result = cc->EvalPoly(result, coeff);

    return result;
}



// Helper — polynomial-approximated reciprocal 1/x for normalization.
Ciphertext<DCRTPoly> EvalInverse(const Ciphertext<DCRTPoly> ciphertext, const double bound, const usint degree){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> sq = cc->EvalMult(ciphertext, 1/(2*bound)); 
    cc->ModReduceInPlace(sq);
    cc->EvalNegateInPlace(sq);
    Ciphertext<DCRTPoly> result = cc->EvalAdd(sq, 2); //1+y
    sq = cc->EvalAdd(sq, 1); // y = 1- x/2*bound.  [0, bound] -> [0, 0.5] -> [0.5, 1]

    for(usint i=1; i<degree; i++){
        sq = cc->EvalMult(sq, sq);
        cc->ModReduceInPlace(sq);
        Ciphertext<DCRTPoly> tmp=cc->EvalAdd(sq, 1);
        result = cc->EvalMult(result, tmp);
        cc->ModReduceInPlace(result);
    }

    result = cc->EvalMult(result, 0.5/bound);
    cc->ModReduceInPlace(result);

    return result;
}




// HECount §2.2 / PrivTopk §II-C — RotSum: recursive rotation-and-add primitive.
// After `round = log2(from/to)` iterations, every slot i holds the sum of
// orig[i], orig[i+to], orig[i+2*to], …, orig[i + (from/to-1)*to].
Ciphertext<DCRTPoly> RotSum(const Ciphertext<DCRTPoly> ciphertext, const int32_t from, const int32_t to, const bool verbose) {
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = ciphertext->Clone();

    if (verbose) cout << "RotSum - from: " << from << ", to: " << to << endl;

    const int32_t round = log2(from / to);
    for (int32_t s = 1; s < round + 1; s++) {
        if (verbose) cout << "Rotating: " << (from >> s) << endl;
        Ciphertext<DCRTPoly> tmp = cc->EvalRotate(result, from >> s);
        result = cc->EvalAdd(result, tmp);
    }

    return result;
}





// Helper — normalize a ciphertext to [-1, 1] before sign-function evaluation.
Ciphertext<DCRTPoly> Normalize(const Ciphertext<DCRTPoly> ciphertext, double bound){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    
    const double div =1 / (double) bound;
    Ciphertext<DCRTPoly> result = cc->EvalMult(ciphertext, div);
    cc->ModReduceInPlace(result);    
    
    return result;
}

// Encrypted Sign Function (parametric form).
// Origin: Cheon, Kim, Kim — "Numerical Method for Comparison on Homomorphically
// Encrypted Numbers", Asiacrypt 2019 (CKK19). Used by PrivTopk §II-B as a
// building block for the comparison matrix M_comp.
//
// `degg` outer iterations of polynomial g, then `degf` iterations of polynomial f.
// Both polynomials are degree-7 odd: f(x) = a₁x + a₃x³ + a₅x⁵ + a₇x⁷ and likewise for g.
// Coefficients are evaluated via a Horner-like inline expansion using
// (x, x³, x⁵, x⁷) prebuilt powers.
//
// `ver` selects the polynomial pair from CKK19's Table 1:
//   ver=1 → degree-3, ver=2 → degree-5, ver=3 → degree-7, ver=4 → degree-9.
// **Only ver=3 is implemented** in this build (the standard recipe PrivTopk uses).
// Other versions are described in the paper but not exposed here; the
// commented original-polymorphic version is preserved in git history.
Ciphertext<DCRTPoly> EncryptedSignFunction(const Ciphertext<DCRTPoly> ciphertext, const usint degf, const usint degg, double bound, const usint ver) {
    if (ver != 3) {
        std::cerr << "EncryptedSignFunction: only ver=3 is implemented (got "
                  << ver << ")." << std::endl;
        return ciphertext->Clone();
    }
    (void) bound;     // currently unused; kept for signature compatibility.

    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = ciphertext->Clone();

    // Polynomial g: degree-7 odd, coefficients
    // (4.4814453125, -16.1884765625, 25.013671875, -12.55859375) for (x, x³, x⁵, x⁷).
    for (usint i = 0; i < degg; i++) {
        vector<Ciphertext<DCRTPoly>> powers(3);
        powers[0] = cc->EvalMult(result, result);          cc->ModReduceInPlace(powers[0]);   // x²
        powers[1] = cc->EvalMult(powers[0], powers[0]);    cc->ModReduceInPlace(powers[1]);   // x⁴
        powers[0] = cc->EvalMult(powers[0], result);       cc->ModReduceInPlace(powers[0]);   // x³
        powers[2] = cc->EvalMult(powers[1], powers[0]);    cc->ModReduceInPlace(powers[2]);   // x⁷
        powers[1] = cc->EvalMult(powers[1], result);       cc->ModReduceInPlace(powers[1]);   // x⁵

        result    = cc->EvalMult(result,    4.4814453125);
        powers[0] = cc->EvalMult(powers[0], -16.1884765625);
        powers[1] = cc->EvalMult(powers[1], 25.013671875);
        powers[2] = cc->EvalMult(powers[2], -12.55859375);
        result = cc->EvalAdd(result, powers[0]);
        result = cc->EvalAdd(result, powers[1]);
        result = cc->EvalAdd(result, powers[2]);
        cc->ModReduceInPlace(result);
    }

    // Polynomial f: degree-7 odd, coefficients
    // (2.1875, -2.1875, 1.3125, -0.3125) for (x, x³, x⁵, x⁷).
    for (usint i = 0; i < degf; i++) {
        vector<Ciphertext<DCRTPoly>> powers(3);
        powers[0] = cc->EvalMult(result, result);          cc->ModReduceInPlace(powers[0]);
        powers[1] = cc->EvalMult(powers[0], powers[0]);    cc->ModReduceInPlace(powers[1]);
        powers[0] = cc->EvalMult(powers[0], result);       cc->ModReduceInPlace(powers[0]);
        powers[2] = cc->EvalMult(powers[1], powers[0]);    cc->ModReduceInPlace(powers[2]);
        powers[1] = cc->EvalMult(powers[1], result);       cc->ModReduceInPlace(powers[1]);

        result    = cc->EvalMult(result,    2.1875);
        powers[0] = cc->EvalMult(powers[0], -2.1875);
        powers[1] = cc->EvalMult(powers[1], 1.3125);
        powers[2] = cc->EvalMult(powers[2], -0.3125);
        result = cc->EvalAdd(result, powers[0]);
        result = cc->EvalAdd(result, powers[1]);
        result = cc->EvalAdd(result, powers[2]);
        cc->ModReduceInPlace(result);
    }
    return result;
}


// ESF convenience wrapper around `EncryptedSignFunction` (CKK19, Asiacrypt 2019).
// Auto-selects polynomial-iteration counts from log₂(bound):
//   degg = 2 by default, log₂(bound)/2 for log₂(bound) > 3;
//   degf = 2 always.
// `lastmod=true`: the final f-iteration uses a half-scaled polynomial that
// maps the sign output {-1, +1} to {0, 1} (saves a downstream rescale).
// `levlimit`: if the running ciphertext level exceeds this, bootstrap is
// invoked before each iteration. Default 100 ≈ never-bootstrap.
// Consumed by PrivTopk §II-B (RankSelect's comparison matrix).
Ciphertext<DCRTPoly> ESF(const Ciphertext<DCRTPoly> ciphertext, const double bound, const bool lastmod, const usint levlimit) {
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = ciphertext->Clone();

    const usint logbound = log2(bound);
    const usint degg = (logbound > 3) ? (logbound / 2) : 2;
    const usint degf = 2;

    vector<Ciphertext<DCRTPoly>> powers(3);

    // g iterations (coefficients: 4.4814453125, -16.1884765625, 25.013671875, -12.55859375).
    for (usint i = 0; i < degg; i++) {
        if (levlimit < result->GetLevel()) result = cc->EvalBootstrap(result, 2, 10);

        powers[0] = cc->EvalMult(result, result);           cc->ModReduceInPlace(powers[0]);   // x²
        powers[1] = cc->EvalMult(powers[0], powers[0]);     cc->ModReduceInPlace(powers[1]);   // x⁴
        powers[0] = cc->EvalMult(powers[0], result);        cc->ModReduceInPlace(powers[0]);   // x³
        powers[2] = cc->EvalMult(powers[1], powers[0]);     cc->ModReduceInPlace(powers[2]);   // x⁷
        powers[1] = cc->EvalMult(powers[1], result);        cc->ModReduceInPlace(powers[1]);   // x⁵

        result    = cc->EvalMult(result,    4.4814453125);
        powers[0] = cc->EvalMult(powers[0], -16.1884765625);
        powers[1] = cc->EvalMult(powers[1], 25.013671875);
        powers[2] = cc->EvalMult(powers[2], -12.55859375);
        result = cc->EvalAdd(result, powers[0]);
        result = cc->EvalAdd(result, powers[1]);
        result = cc->EvalAdd(result, powers[2]);
        cc->ModReduceInPlace(result);
    }

    // f iterations. The last iteration optionally uses half-scaled coefficients
    // (1.09375, -1.09375, 0.65625, -0.15625) + a final `+0.5` shift so the
    // {-1, +1} → {0, 1} mapping is folded into the polynomial.
    for (usint i = 0; i < degf; i++) {
        if (levlimit < result->GetLevel()) result = cc->EvalBootstrap(result, 2, 10);

        powers[0] = cc->EvalMult(result, result);           cc->ModReduceInPlace(powers[0]);
        powers[1] = cc->EvalMult(powers[0], powers[0]);     cc->ModReduceInPlace(powers[1]);
        powers[0] = cc->EvalMult(powers[0], result);        cc->ModReduceInPlace(powers[0]);
        powers[2] = cc->EvalMult(powers[1], powers[0]);     cc->ModReduceInPlace(powers[2]);
        powers[1] = cc->EvalMult(powers[1], result);        cc->ModReduceInPlace(powers[1]);

        const bool finalIterWithLastMod = (i == degf - 1) && lastmod;
        const double c1 = finalIterWithLastMod ?  1.09375  :  2.1875;
        const double c3 = finalIterWithLastMod ? -1.09375  : -2.1875;
        const double c5 = finalIterWithLastMod ?  0.65625  :  1.3125;
        const double c7 = finalIterWithLastMod ? -0.15625  : -0.3125;

        result    = cc->EvalMult(result,    c1);
        powers[0] = cc->EvalMult(powers[0], c3);
        powers[1] = cc->EvalMult(powers[1], c5);
        powers[2] = cc->EvalMult(powers[2], c7);
        result = cc->EvalAdd(result, powers[0]);
        result = cc->EvalAdd(result, powers[1]);
        result = cc->EvalAdd(result, powers[2]);
        cc->ModReduceInPlace(result);
        if (finalIterWithLastMod) result = cc->EvalAdd(result, 0.5);
    }

    return result;
}


// lastmod false version + independent final lastmod

// Quantized ESF over multi-segment ciphertext (per-segment CKK19 sign +
// recurrence-based reconstruction). Used by PrivTopk §V-B2 for the
// arbitrary-precision RankSelect path.
// `ciphertext[0]` holds the high-order segment, `ciphertext.back()` the lowest.
// Per-segment ESF (without lastmod) then ESFQReconstruct combines them via
// the (1 - r²) log-depth reduction.
Ciphertext<DCRTPoly> ESFQ(const vector<Ciphertext<DCRTPoly>> ciphertext, const double bound, const bool lastmod, const usint levlimit) {
    const int32_t numCt = ciphertext.size();
    if (numCt == 1) return ESF(ciphertext[0], bound, lastmod, levlimit);

    vector<Ciphertext<DCRTPoly>> segResults(numCt);
    for (int32_t i = 0; i < numCt; i++) segResults[i] = ESF(ciphertext[i], bound, false, levlimit);

    return ESFQReconstruct(segResults, lastmod);
}



// Reconstruct ESFQ output from per-segment partials.
// Each input segment holds a CKK19-style ESF result in {-1, 0, +1} (per
// ESF without lastmod). Combines them via the recurrence
//   combined(high, low) = high + (1 - high²)·low
// applied as a log-depth tree (numCt must be a power of 2).
// `lastmod=true` shifts the final {-1, +1} output to {0, 1}.
// Used by PrivTopk §V-B2's arbitrary-precision path.
Ciphertext<DCRTPoly> ESFQReconstruct(const vector<Ciphertext<DCRTPoly>> ciphertext, const bool lastmod) {
    const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
    const int32_t numCt = ciphertext.size();

    // Log-depth tree reduction. Each round pairs index j*interval with
    // j*interval + interval/2 and combines via the (1 - high²)·low recurrence.
    vector<Ciphertext<DCRTPoly>> result(numCt / 2);
    for (int32_t j = 0; j < numCt / 2; j++) result[j] = ciphertext[2 * j]->Clone();

    for (int32_t i = 0; i < log2(numCt); i++) {
        const int32_t interval = 1 << i;
        for (int32_t j = 0; j < (numCt >> (i + 1)); j++) {
            Ciphertext<DCRTPoly> tmp = cc->EvalMult(result[j * interval], result[j * interval]);
            cc->ModReduceInPlace(tmp);
            tmp = cc->EvalSub(1, tmp);                                       // 1 - high²
            const auto &low = (i == 0) ? ciphertext[2 * j + 1]
                                       : result[j * interval + interval / 2];
            tmp = cc->EvalMult(low, tmp);
            cc->ModReduceInPlace(tmp);
            result[j * interval] = cc->EvalAdd(result[j * interval], tmp);
        }
    }

    if (lastmod) {
        result[0] = cc->EvalAdd(result[0], 1);
        result[0] = cc->EvalMult(result[0], 0.5);
        cc->ModReduceInPlace(result[0]);
    }
    return result[0];
}


// // 



// Debug helper — fake bootstrap via decrypt-encrypt round-trip (test/debug only).
// Hardcoded `depth=19` is the noise budget for the re-encoded plaintext;
// adjust if the benchmark needs a different post-fakeboot starting level.
Ciphertext<DCRTPoly> FakeBoot(const Ciphertext<DCRTPoly> ciphertext, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys, bool verbose) {
    if (verbose) cout << "Before: " << ciphertext->GetLevel() << endl;

    Plaintext decrypted;
    cc->Decrypt(keys.secretKey, ciphertext, &decrypted);
    vector<double> vals = decrypted->GetRealPackedValue();

    constexpr usint kFakeBootDepth = 19;
    Plaintext            reencodedPt = cc->MakeCKKSPackedPlaintext(vals, 1, kFakeBootDepth);
    Ciphertext<DCRTPoly> result      = cc->Encrypt(keys.publicKey, reencodedPt);

    if (verbose) cout << "After: " << result->GetLevel() << endl;
    return result;
}


// Debug helper — print the decrypted plaintext for inspection during a benchmark.
void CheckDecrypted(const Ciphertext<DCRTPoly> ciphertext, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys) {
    const int32_t batchSize = cc->GetEncodingParams()->GetBatchSize();

    Plaintext result;
    cout << "current level: " << ciphertext->GetLevel() << endl;
    cc->Decrypt(keys.secretKey, ciphertext, &result);

    vector<double> vals = result->GetRealPackedValue();
    cout << "vals size: " << vals.size() << endl;

    usint nonzeros = 0;
    for (int32_t i = 0; i < batchSize; i++) {
        if (vals[i] >= 0.00001) nonzeros += 1;
    }
    cout << "number of nonzeros: " << nonzeros << endl;

    result->SetLength(8);
    cout << result << endl;
}




} // namespace ckkseif
