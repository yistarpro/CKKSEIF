#include "openfhe.h"
#include "test_count.h"
#include "test_core.h"
#include "counting.h"
#include "algorithms.h"
#include "utils.h"
#include "bench_runner.h"

#include <omp.h>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

    // HECount §3.1 Alg 1 — Naive Counting. Inputs are `size`-many discrete
    // integers in [0, bound); output is a vector of `bound` ciphertexts each
    // holding the count of one residue class. Baseline for Table 2.
    void NaiveCountTest(const uint32_t scaleModSize, const uint32_t bound, usint size, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 2320 / scaleModSize - 4;
        if (size == 0) size = batchSize;

        vector<double>  timeEval(iteration);

        printBenchHeader("NaiveCountTest", {
            {"bound",     to_string(bound)},
            {"size",      to_string(size)},
            {"iter",      to_string(iteration)},
            {"scaleMod",  to_string(scaleModSize)},
            {"multDepth", to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForEmb(keys.secretKey, cc, size);

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec   = randomIntArray(size, bound);
        vector<double>        packedVec  = fullCopy(inputVec, batchSize, size);
        Plaintext             inputPt    = cc->MakeCKKSPackedPlaintext(packedVec);
        Ciphertext<DCRTPoly>  inputCt    = cc->Encrypt(keys.publicKey, inputPt);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Plaintext resultPt;
        double    worstPrec = 100;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            vector<Ciphertext<DCRTPoly>> countCts = NaiveCount(inputCt, bound, size);
            timeEval[i] = TOC(t);

            for (usint r = 0; r < countCts.size(); r++) {
                cc->Decrypt(keys.secretKey, countCts[r], &resultPt);
                double residuePrec = countprecisionMute(resultPt, inputVec, size, r);
                if (residuePrec < worstPrec) worstPrec = residuePrec;
                // Bail out of the per-residue check if precision is anomalous
                // (likely a parameter bug) — print the offending residue.
                if (worstPrec < 3 || worstPrec > 90) {
                    resultPt->SetLength(16);
                    cout << "  residue " << r << " :: " << resultPt
                         << " (level=" << countCts[r]->GetLevel() << ")" << endl;
                    break;
                }
            }
            cout << "  iter " << i << ": " << timeEval[i]
                 << " ms, worst residue precision=" << worstPrec << endl;
        }

        //─── 5. Summary ─────────────────────────────────────────────────────
        cout << "Total: "; statTime(timeEval, iteration);
    }


    // HECount §3.2 Alg 2 + §3.3 Alg 5 — CodedCount with BasisExp.
    // Input value = Σ_i x_i · base^i. Pipeline: ToOHE → BasisExp → Count.
    // `exponentBound` = degree of BasisExp tensor expansion (1 = none, paper's
    // Alg 2; ≥2 = CountEB / Alg 5). Table 2.
    void CodedCountTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint exponentbound, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 2320 / scaleModSize - 4;
        if (size == 0) size = batchSize;
        const usint     totalBound = (usint) pow(base, dim);

        vector<double>  timeToOHE   (iteration);
        vector<double>  timeBasisExp(iteration);
        vector<double>  timeCount   (iteration);
        vector<double>  timeTotal   (iteration);

        printBenchHeader("CodedCountTest", {
            {"size",          to_string(size)},
            {"base",          to_string(base)},
            {"dim",           to_string(dim)},
            {"totalBound",    to_string(totalBound)},
            {"exponentBound", to_string(exponentbound)},
            {"iter",          to_string(iteration)},
            {"scaleMod",      to_string(scaleModSize)},
            {"multDepth",     to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForEmb(keys.secretKey, cc, size);

        //─── 3. Inputs (base-decomposed) ────────────────────────────────────
        vector<double>               inputVec(size);
        vector<Ciphertext<DCRTPoly>> digitCts(dim);
        usint currentBase = 1;
        for (usint d = 0; d < dim; d++) {
            vector<double> digitVec = randomIntArray(size, base);
            for (usint j = 0; j < size; j++) inputVec[j] += digitVec[j] * currentBase;

            vector<double> packed = fullCopy(digitVec, batchSize, size);
            currentBase *= base;
            Plaintext digitPt = cc->MakeCKKSPackedPlaintext(packed);
            digitCts[d]       = cc->Encrypt(keys.publicKey, digitPt);
        }

        //─── 4. Timed evaluation (three phases) ─────────────────────────────
        Plaintext resultPt;
        double    worstPrec = 100;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            auto oheCts   = ToOHE(digitCts, base);
            timeToOHE[i]  = TOC(t);

            TIC(t);
            auto basisCts = BasisExp(oheCts, base, exponentbound);
            timeBasisExp[i] = TOC(t);

            TIC(t);
            auto countCts = Count(basisCts, base, size, dim, exponentbound, 0);
            timeCount[i]  = TOC(t);

            timeTotal[i] = timeToOHE[i] + timeBasisExp[i] + timeCount[i];

            for (usint r = 0; r < countCts.size(); r++) {
                cc->Decrypt(keys.secretKey, countCts[r], &resultPt);
                double residuePrec = codedcountprecisionMute(resultPt, inputVec, size, r, false);
                if (residuePrec < worstPrec) worstPrec = residuePrec;
                if (worstPrec < 3 || worstPrec > 90) {
                    resultPt->SetLength(16);
                    cout << "  residue " << r << " :: " << resultPt << endl;
                    break;
                }
            }
            cout << "  iter " << i
                 << ": ToOHE=" << timeToOHE[i]
                 << ", BasisExp=" << timeBasisExp[i]
                 << ", Count=" << timeCount[i]
                 << ", total=" << timeTotal[i]
                 << " ms, prec=" << worstPrec << endl;
        }

        //─── 5. Summary ─────────────────────────────────────────────────────
        cout << "ToOHE:    "; statTime(timeToOHE,    iteration);
        cout << "BasisExp: "; statTime(timeBasisExp, iteration);
        cout << "Count:    "; statTime(timeCount,    iteration);
        cout << "Total:    "; statTime(timeTotal,    iteration);
    }

    // HECount §3.4 Alg 7 — Parallelized Coded Counting (ParalCount).
    // SIMD variant of CodedCountTest: pipeline is ToOHESIMD → ParalBasisExp →
    // ParalCount, with `maxlen` real items packed per `size`-slot block.
    // Per Table 3 the validation phase is left out (correctness is checked by
    // running CodedCountTest in parallel with the same seed).
    void CodedCountSIMDTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint maxlen, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 2320 / scaleModSize - 4;
        if (size == 0) size = batchSize;
        const usint     totalBound = (usint) pow(base, dim);

        vector<double>  timeToOHE   (iteration);
        vector<double>  timeBasisExp(iteration);
        vector<double>  timeCount   (iteration);
        vector<double>  timeTotal   (iteration);

        printBenchHeader("CodedCountSIMDTest", {
            {"size",       to_string(size)},
            {"maxlen",     to_string(maxlen)},
            {"base",       to_string(base)},
            {"dim",        to_string(dim)},
            {"totalBound", to_string(totalBound)},
            {"iter",       to_string(iteration)},
            {"scaleMod",   to_string(scaleModSize)},
            {"multDepth",  to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForEmb(keys.secretKey, cc, size);
        AddRotKeyForCountSIMD(keys.secretKey, cc, base, size, batchSize, totalBound);

        //─── 3. Inputs (base-decomposed, `maxlen` non-zero positions) ───────
        vector<double>               inputVec(size);
        vector<Ciphertext<DCRTPoly>> digitCts(dim);
        usint currentBase = 1;
        for (usint d = 0; d < dim; d++) {
            vector<double> digitVec = randomIntArray(maxlen, base);
            for (usint j = 0; j < maxlen; j++) inputVec[j] += digitVec[j] * currentBase;

            vector<double> packed = fullCopy(digitVec, batchSize, size);
            currentBase *= base;
            Plaintext digitPt = cc->MakeCKKSPackedPlaintext(packed);
            digitCts[d]       = cc->Encrypt(keys.publicKey, digitPt);
        }

        //─── 4. Timed evaluation ────────────────────────────────────────────
        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            auto oheCts     = ToOHESIMD(digitCts, base, size);
            timeToOHE[i]    = TOC(t);

            TIC(t);
            auto basisCts   = ParalBasisExp(oheCts, base, size, 0);
            timeBasisExp[i] = TOC(t);

            TIC(t);
            auto countCts   = ParalCount(basisCts, base, size, maxlen, dim);
            timeCount[i]    = TOC(t);

            timeTotal[i] = timeToOHE[i] + timeBasisExp[i] + timeCount[i];
            cout << "  iter " << i
                 << ": ToOHE=" << timeToOHE[i]
                 << ", BasisExp=" << timeBasisExp[i]
                 << ", Count=" << timeCount[i]
                 << ", total=" << timeTotal[i]
                 << " ms, level=" << countCts[0]->GetLevel() << endl;
        }

        //─── 5. Summary ─────────────────────────────────────────────────────
        cout << "ToOHE:    "; statTime(timeToOHE,    iteration);
        cout << "BasisExp: "; statTime(timeBasisExp, iteration);
        cout << "Count:    "; statTime(timeCount,    iteration);
        cout << "Total:    "; statTime(timeTotal,    iteration);
    }

    // HECount §4.2 / Fig. 2 — n-gram extraction.
    // Three-phase pipeline: BasisConstruction (ToOHE + BasisExp) → NgramBasis
    // (combine n consecutive basis elements via rotations) → Ngram (count over
    // the n-gram basis). `ratio` selects a partial bound for sparse n-gram
    // tables (0 ⇒ full basis). Table 4.
    void NgramTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint exponentbound, const usint n, const double ratio, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 2320 / scaleModSize - 4;
        if (size == 0) size = batchSize;

        const usint   bound        = (usint) pow(pow(base, dim), n);
        usint         partialBound = (usint)(((double) bound * ratio) / 100.0);
        if (partialBound > bound || partialBound == 0) partialBound = bound;

        vector<double>  timeBasisCons (iteration);
        vector<double>  timeNgramBasis(iteration);
        vector<double>  timeNgram     (iteration);
        vector<double>  timeTotal     (iteration);

        printBenchHeader("NgramTest", {
            {"n",             to_string(n)},
            {"size",          to_string(size)},
            {"base",          to_string(base)},
            {"dim",           to_string(dim)},
            {"perDimBound",   to_string((usint) pow(base, dim))},
            {"partialBound",  to_string(partialBound)},
            {"exponentBound", to_string(exponentbound)},
            {"ratio%",        to_string(ratio)},
            {"iter",          to_string(iteration)},
            {"scaleMod",      to_string(scaleModSize)},
            {"multDepth",     to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForEmb(keys.secretKey, cc, size);

        // n-gram pulls n-1 left-rotations (NB: original only generates rots
        // {-1, -2} regardless of n — preserved here).
        vector<int32_t> ngramRots(n - 1);
        for (int32_t r = 1; r < 3; r++) ngramRots[r - 1] = -r;
        cc->EvalRotateKeyGen(keys.secretKey, ngramRots);

        //─── 3. Inputs (base-decomposed) ────────────────────────────────────
        vector<double>               inputVec(size);
        vector<Ciphertext<DCRTPoly>> digitCts(dim);
        usint currentBase = 1;
        for (usint d = 0; d < dim; d++) {
            vector<double> digitVec = randomIntArray(size, base);
            for (usint j = 0; j < size; j++) inputVec[j] += digitVec[j] * currentBase;

            vector<double> packed = fullCopy(digitVec, batchSize, size);
            currentBase *= base;
            Plaintext digitPt = cc->MakeCKKSPackedPlaintext(packed);
            digitCts[d]       = cc->Encrypt(keys.publicKey, digitPt);
        }

        //─── 4. Timed evaluation (three phases) ─────────────────────────────
        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            auto oheCts        = ToOHE(digitCts, base);
            auto basisCts      = BasisExp(oheCts, base, exponentbound, true);
            timeBasisCons[i]   = TOC(t);
            vector<Ciphertext<DCRTPoly>>().swap(oheCts);

            TIC(t);
            auto ngramBasisCts = NgramBasis(basisCts, n);
            timeNgramBasis[i]  = TOC(t);
            vector<Ciphertext<DCRTPoly>>().swap(basisCts);

            TIC(t);
            auto resultCts     = Ngram(ngramBasisCts, base, size, dim, exponentbound, n, ratio, true);
            timeNgram[i]       = TOC(t);

            timeTotal[i] = timeBasisCons[i] + timeNgramBasis[i] + timeNgram[i];
            cout << "  iter " << i
                 << ": BasisCons=" << timeBasisCons[i]
                 << ", NgramBasis=" << timeNgramBasis[i]
                 << ", Ngram=" << timeNgram[i]
                 << ", total=" << timeTotal[i]
                 << " ms, level=" << resultCts[0]->GetLevel() << endl;
        }

        //─── 5. Summary ─────────────────────────────────────────────────────
        cout << "BasisCons:  "; statTime(timeBasisCons,  iteration);
        cout << "NgramBasis: "; statTime(timeNgramBasis, iteration);
        cout << "Ngram:      "; statTime(timeNgram,      iteration);
        cout << "Total:      "; statTime(timeTotal,      iteration);
    }

    // HECount §4.3 — Monolithic IR pipeline: query encoding + TF acquisition
    // + IR in a single CKKS context.
    // Pipeline: query digits → ToOHE → BasisExp → Count (TF) → IDFMult →
    // DistanceComparison vs. corpus TF-IDF → Retrieval.
    //
    // **Not currently dispatched.** `--info` instead runs (A) one standalone
    // CodedCountSIMDTest for TF-acquisition cost, then (B) three corpus-size
    // sweeps via InfoRetrievalAfterTFTest. That split matches the paper's
    // Table 5 reporting structure and lets TF (corpus-independent) be measured
    // once instead of re-run per corpus size.
    //
    // This function is the predecessor unified version: less flexible than
    // the split form (re-runs TF acquisition for every corpus size, hardcodes
    // multDepth=43 and a literal `256` Count size, single context across
    // phases). Kept as a paper-aligned reference, similar to `bootPacked` in
    // PrivTopk.
    void InfoRetrievalTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint vocabsize, const usint exponentbound, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 43;     // explicit, not the 2320/Δ-4 formula
        if (size == 0) size = batchSize;

        vector<double>  timeTFIDF   (iteration);
        vector<double>  timeDistance(iteration);
        vector<double>  timeRetrieve(iteration);
        vector<double>  timeTotal   (iteration);

        printBenchHeader("InfoRetrievalTest", {
            {"size",          to_string(size)},
            {"vocabsize",     to_string(vocabsize)},
            {"base",          to_string(base)},
            {"dim",           to_string(dim)},
            {"totalBound",    to_string((usint) pow(base, dim))},
            {"exponentBound", to_string(exponentbound)},
            {"iter",          to_string(iteration)},
            {"scaleMod",      to_string(scaleModSize)},
            {"multDepth",     to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForIR(keys.secretKey, cc, size, batchSize);

        //─── 3. Inputs (corpus + query, loaded from disk) ───────────────────
        Plaintext           text      = LoadText (cc, size, 1024);
        vector<Plaintext>   tfidf     = LoadTFIDF(cc, size, vocabsize, batchSize);
        vector<Plaintext>   idf       = LoadIDF  (cc, size, vocabsize, batchSize, false, (usint) pow(base, dim) - 1);
        vector<Plaintext>   queryPts  = LoadQuery(cc, base, dim, size, batchSize, /*queryid=*/8);

        vector<Ciphertext<DCRTPoly>> queryCts(dim);
        for (usint d = 0; d < dim; d++) queryCts[d] = cc->Encrypt(keys.publicKey, queryPts[d]);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Plaintext resultPt;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            auto oheCts   = ToOHE(queryCts, base);
            auto basisCts = BasisExp(oheCts, base, exponentbound);
            auto countCts = Count(basisCts, base, 256, dim, exponentbound, size);
            auto docCts   = IDFMult(countCts, size, idf);
            timeTFIDF[i]  = TOC(t);
            vector<Ciphertext<DCRTPoly>>().swap(oheCts);
            vector<Ciphertext<DCRTPoly>>().swap(basisCts);
            vector<Ciphertext<DCRTPoly>>().swap(countCts);

            TIC(t);
            auto distCts     = DistanceComparison(docCts, size, tfidf);
            timeDistance[i]  = TOC(t);

            TIC(t);
            auto retrievedCt = Retrieval(distCts[2], size, text);
            timeRetrieve[i]  = TOC(t);

            timeTotal[i] = timeTFIDF[i] + timeDistance[i] + timeRetrieve[i];

            cc->Decrypt(keys.secretKey, retrievedCt, &resultPt);
            writetext      (resultPt, size, to_string(size) + to_string(i) + "retrievednumber.txt", 1024);
            mapandwritetext(resultPt, size, to_string(size) + to_string(i) + "retrievedtext.txt",   1024);

            resultPt->SetLength(16);
            cout << "  iter " << i
                 << ": TFIDF=" << timeTFIDF[i]
                 << ", Dist=" << timeDistance[i]
                 << ", Retrieve=" << timeRetrieve[i]
                 << ", total=" << timeTotal[i]
                 << " ms, level=" << retrievedCt->GetLevel() << endl;
        }

        //─── 5. Summary ─────────────────────────────────────────────────────
        cout << "TFIDF:    "; statTime(timeTFIDF,    iteration);
        cout << "Distance: "; statTime(timeDistance, iteration);
        cout << "Retrieve: "; statTime(timeRetrieve, iteration);
        cout << "Total:    "; statTime(timeTotal,    iteration);
    }



    // HECount §4.3 — IR pipeline with precomputed term frequency.
    // Skips ToOHE/BasisExp/Count (the TF acquisition stages) and starts from
    // `LoadQueryTF`, which returns the query's term-frequency vector already.
    // Pipeline: IDFMult → DistanceComparison → Retrieval. Table 5 (short path).
    // NB: in the original, c1[0] and c1[1] are both encrypted from querytf[0]
    // (likely a typo for c1[0]=querytf[0], c1[i]=querytf[i-1] starting at i=1).
    // Preserved as-is; flagged here.
    void InfoRetrievalAfterTFTest(const uint32_t scaleModSize, usint size, const usint vocabsize, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 2320 / scaleModSize - 4;
        if (size == 0) size = batchSize;
        const usint     dim       = 1024 / size;

        vector<double>  timeTFIDF   (iteration);
        vector<double>  timeDistance(iteration);
        vector<double>  timeRetrieve(iteration);
        vector<double>  timeTotal   (iteration);

        printBenchHeader("InfoRetrievalAfterTFTest", {
            {"size",      to_string(size)},
            {"vocabsize", to_string(vocabsize)},
            {"dim",       to_string(dim)},
            {"iter",      to_string(iteration)},
            {"scaleMod",  to_string(scaleModSize)},
            {"multDepth", to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForPo2(keys.secretKey, cc, batchSize);

        //─── 3. Inputs (corpus + precomputed query TF, loaded from disk) ────
        Plaintext         text    = LoadText   (cc, size, 1024);
        vector<Plaintext> tfidf   = LoadTFIDF  (cc, size, vocabsize, batchSize);
        vector<Plaintext> idf     = LoadIDF    (cc, size, vocabsize, batchSize, false, 1023);
        vector<Plaintext> queryTf = LoadQueryTF(cc, size, 256, 1024, batchSize, /*queryid=*/8);

        vector<Ciphertext<DCRTPoly>> queryCts(dim + 1);
        queryCts[0] = cc->Encrypt(keys.publicKey, queryTf[0]);     // FIXME: duplicates querytf[0]
        for (usint i = 0; i < dim; i++) queryCts[i + 1] = cc->Encrypt(keys.publicKey, queryTf[i]);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Plaintext resultPt;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            auto docCts      = IDFMult(queryCts, size, idf);
            timeTFIDF[i]     = TOC(t);

            TIC(t);
            auto distCts     = DistanceComparison(docCts, size, tfidf);
            timeDistance[i]  = TOC(t);

            TIC(t);
            auto retrievedCt = Retrieval(distCts[2], size, text);
            timeRetrieve[i]  = TOC(t);

            timeTotal[i] = timeTFIDF[i] + timeDistance[i] + timeRetrieve[i];

            cc->Decrypt(keys.secretKey, retrievedCt, &resultPt);
            writetext      (resultPt, size, to_string(size) + to_string(i) + "retrievednumber.txt", 1024);
            mapandwritetext(resultPt, size, to_string(size) + to_string(i) + "retrievedtext.txt",   1024);

            resultPt->SetLength(16);
            cout << "  iter " << i
                 << ": TFIDF=" << timeTFIDF[i]
                 << ", Dist=" << timeDistance[i]
                 << ", Retrieve=" << timeRetrieve[i]
                 << ", total=" << timeTotal[i]
                 << " ms, level=" << retrievedCt->GetLevel() << endl;
        }

        //─── 5. Summary ─────────────────────────────────────────────────────
        cout << "TFIDF:    "; statTime(timeTFIDF,    iteration);
        cout << "Distance: "; statTime(timeDistance, iteration);
        cout << "Retrieve: "; statTime(timeRetrieve, iteration);
        cout << "Total:    "; statTime(timeTotal,    iteration);
    }





} // namespace ckkseif
