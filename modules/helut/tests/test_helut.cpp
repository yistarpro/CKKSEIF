#include "openfhe.h"
#include "test_helut.h"
#include "test_core.h"
#include "embedding.h"
#include "lookup.h"
#include "algorithms.h"
#include "utils.h"
#include "bench_runner.h"

#include <omp.h>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

    // HELUT §4.1 / Eq. 9 — HELUT-LT (linear-transform form, no coding).
    // Evaluates T(ct) = E · OHE_p(ct) on a full bound-entry table.
    void LUTLTTest(const usint bound, const usint outputdimension, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  scaleModSize = 35;
        const uint32_t  multDepth    = 22;

        vector<double>  timeEval(iteration);

        printBenchHeader("LUTLTTest", {
            {"bound",      to_string(bound)},
            {"outputDim",  to_string(outputdimension)},
            {"iter",       to_string(iteration)},
            {"scaleMod",   to_string(scaleModSize)},
            {"multDepth",  to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize);
        auto cc   = ctx.cc;
        auto keys = ctx.keys;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = randomIntArray(batchSize, bound);
        vector<double>        table    = randomRealArray(bound * outputdimension, 1.0);

        Plaintext             inputPt  = cc->MakeCKKSPackedPlaintext(inputVec);
        Ciphertext<DCRTPoly>  inputCt  = cc->Encrypt(keys.publicKey, inputPt);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        vector<Ciphertext<DCRTPoly>> resultCts;
        Plaintext                    resultPt;
        vector<double>               expectedVec(batchSize);
        usint                        worstPrec = scaleModSize;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCts   = HELUT_LT(inputCt, table, bound, outputdimension);
            timeEval[i] = TOC(t);

            for (usint d = 0; d < outputdimension; d++) {
                cc->Decrypt(keys.secretKey, resultCts[d], &resultPt);
                for (usint k = 0; k < batchSize; k++) {
                    expectedVec[k] = table[bound * d + (usint) inputVec[k]];
                }
                usint dimPrec = precisionMute(resultPt, expectedVec, batchSize, 1);
                if (dimPrec < worstPrec) worstPrec = dimPrec;
            }
            cout << "  iter " << i << ": " << timeEval[i]
                 << " ms, worst-dim precision=" << worstPrec << " bits" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cout << "Estimated level: " << resultPt->GetLevel() << endl;
        cout << "Total: "; statTime(timeEval, iteration);
    }

    // HELUT Alg 3 — HELUT with Coded Input (HELUT-CI).
    // Splits the input index into `numcode` segments (each in [0, bound)), then
    // looks up a table of size bound^numcode.
    // TODO: generalize validation to arbitrary numcode (currently asserts == 2
    // because the bound^2 totalbound expression and the 2-input fold below
    // only handle that case — HELUT_CI itself supports general numcode).
    void LUTCITest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {
        if (numcode != 2) {
            cerr << "LUTCITest: numcode must be 2 (got " << numcode
                 << "); validation only implemented for the 2-segment case." << endl;
            return;
        }

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  scaleModSize = 35;
        const uint32_t  multDepth    = 22;
        const usint     totalBound   = bound * bound;     // numcode = 2

        vector<double>  timeEval(iteration);

        printBenchHeader("LUTCITest", {
            {"bound",      to_string(bound)},
            {"numcode",    to_string(numcode)},
            {"outputDim",  to_string(outputdimension)},
            {"iter",       to_string(iteration)},
            {"scaleMod",   to_string(scaleModSize)},
            {"multDepth",  to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize);
        auto cc   = ctx.cc;
        auto keys = ctx.keys;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<vector<double>>       inputVecs(numcode);
        for (usint s = 0; s < numcode; s++) inputVecs[s] = randomIntArray(batchSize, bound);

        vector<double>               table = randomRealArray(totalBound * outputdimension, 1.0);

        vector<Ciphertext<DCRTPoly>> inputCts(numcode);
        for (usint s = 0; s < numcode; s++) {
            Plaintext segPt = cc->MakeCKKSPackedPlaintext(inputVecs[s]);
            inputCts[s]     = cc->Encrypt(keys.publicKey, segPt);
        }

        //─── 4. Timed evaluation ────────────────────────────────────────────
        vector<Ciphertext<DCRTPoly>> resultCts;
        Plaintext                    resultPt;
        vector<double>               expectedVec(batchSize);
        usint                        worstPrec = scaleModSize;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCts   = HELUT_CI(inputCts, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);

            for (usint d = 0; d < outputdimension; d++) {
                cc->Decrypt(keys.secretKey, resultCts[d], &resultPt);
                usint base = totalBound * d;
                for (usint k = 0; k < batchSize; k++) {
                    usint idx      = (usint) inputVecs[0][k] + ((usint) inputVecs[1][k]) * bound;
                    expectedVec[k] = table[base + idx];
                }
                usint dimPrec = precisionMute(resultPt, expectedVec, batchSize, 1);
                if (dimPrec < worstPrec) worstPrec = dimPrec;
            }
            cout << "  iter " << i << ": " << timeEval[i]
                 << " ms, worst-dim precision=" << worstPrec << " bits" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cout << "Estimated level: " << resultPt->GetLevel() << endl;
        cout << "Total: "; statTime(timeEval, iteration);
    }



    // HELUT Alg 4 — CodedHELUT. Decomposes the input into `numcode` segments
    // and sums per-segment lookups (additive coding instead of product coding).
    void CodedLUTTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  scaleModSize = 35;
        const uint32_t  multDepth    = 22;

        vector<double>  timeEval(iteration);

        printBenchHeader("CodedLUTTest", {
            {"bound",      to_string(bound)},
            {"numcode",    to_string(numcode)},
            {"outputDim",  to_string(outputdimension)},
            {"iter",       to_string(iteration)},
            {"scaleMod",   to_string(scaleModSize)},
            {"multDepth",  to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize);
        auto cc   = ctx.cc;
        auto keys = ctx.keys;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<vector<double>>       inputVecs(numcode);
        for (usint s = 0; s < numcode; s++) inputVecs[s] = randomIntArray(batchSize, bound);

        vector<double>               table = randomRealArray(bound * numcode * outputdimension, 1.0);

        vector<Ciphertext<DCRTPoly>> inputCts(numcode);
        for (usint s = 0; s < numcode; s++) {
            Plaintext segPt = cc->MakeCKKSPackedPlaintext(inputVecs[s]);
            inputCts[s]     = cc->Encrypt(keys.publicKey, segPt);
        }

        //─── 4. Timed evaluation ────────────────────────────────────────────
        vector<Ciphertext<DCRTPoly>> resultCts;
        Plaintext                    resultPt;
        vector<double>               expectedVec(batchSize);
        usint                        worstPrec = scaleModSize;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCts   = CodedHELUT(inputCts, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);

            for (usint d = 0; d < outputdimension; d++) {
                cc->Decrypt(keys.secretKey, resultCts[d], &resultPt);
                for (usint k = 0; k < batchSize; k++) {
                    expectedVec[k] = 0;
                    for (usint s = 0; s < numcode; s++) {
                        usint base      = s * bound + bound * numcode * d;
                        expectedVec[k] += table[base + (usint) inputVecs[s][k]];
                    }
                }
                usint dimPrec = precisionMute(resultPt, expectedVec, batchSize, 1);
                if (dimPrec < worstPrec) worstPrec = dimPrec;
            }
            cout << "  iter " << i << ": " << timeEval[i]
                 << " ms, worst-dim precision=" << worstPrec << " bits" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cout << "Estimated level: " << resultPt->GetLevel() << endl;
        cout << "Total: "; statTime(timeEval, iteration);
    }


    // HELUT §4.3 — CodedHELUT+p1 (SIMD-packed variant on top of Alg 4).
    // Uses embedding-style rotation keys; `EncryptForSIMD` packs `numcode`
    // segments per ciphertext at stride `bound`.
    void CodedLUTSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  scaleModSize = 35;
        const uint32_t  multDepth    = 22;
        const usint     stride       = bound * numcode;
        const usint     packedSlots  = batchSize / stride;

        vector<double>  timeEval(iteration);

        printBenchHeader("CodedLUTSIMDTest", {
            {"bound",      to_string(bound)},
            {"numcode",    to_string(numcode)},
            {"outputDim",  to_string(outputdimension)},
            {"iter",       to_string(iteration)},
            {"scaleMod",   to_string(scaleModSize)},
            {"multDepth",  to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize);
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForEmb(keys.secretKey, cc, stride);     // embedding-style rotation keys

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = randomIntArray(batchSize / bound, bound);
        vector<double>        table    = randomRealArray(bound * numcode * outputdimension, 1.0);
        auto                  inputCts = EncryptForSIMD(inputVec, bound, keys.publicKey, cc);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        vector<Ciphertext<DCRTPoly>> resultCts;
        Plaintext                    resultPt;
        vector<double>               expectedVec(packedSlots);
        usint                        worstPrec = scaleModSize;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCts   = CodedHELUT_P1(inputCts, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);

            for (usint d = 0; d < outputdimension; d++) {
                cc->Decrypt(keys.secretKey, resultCts[d], &resultPt);
                for (usint k = 0; k < packedSlots; k++) {
                    expectedVec[k] = 0;
                    for (usint s = 0; s < numcode; s++) {
                        usint base      = s * bound + bound * numcode * d;
                        expectedVec[k] += table[base + (usint) inputVec[k * numcode + s]];
                    }
                }
                usint dimPrec = precisionMute(resultPt, expectedVec, packedSlots, stride);
                if (dimPrec < worstPrec) worstPrec = dimPrec;
            }
            cout << "  iter " << i << ": " << timeEval[i]
                 << " ms, worst-dim precision=" << worstPrec << " bits" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cout << "Estimated level: " << resultPt->GetLevel() << endl;
        cout << "Total: "; statTime(timeEval, iteration);
    }

    // HELUT Table 1 — Synthetic-table LUT sweep across the four primitives.
    // LUTLTTest gets the full bound^numcode table; the coded variants get the
    // segmented (bound, numcode) form.
    void LUTSynthTests(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {
        const usint totalbound = 1u << (usint)(log2(bound) * numcode);

        LUTLTTest      (totalbound,        outputdimension, iteration);
        LUTCITest      (bound, numcode,    outputdimension, iteration);
        CodedLUTTest   (bound, numcode,    outputdimension, iteration);
        CodedLUTSIMDTest(bound, numcode,   outputdimension, iteration);
    }




    // HELUT Table 2 — CodedHELUT on a real CompressedEmbedding (GloVe / GPT-2).
    // Reads codebook weights via `CompressedEmbedding(numcode, bound, outputdim)`
    // (resolves to data/<corpus><dim>d<numcode>_<bound>weight.txt).
    void EmbeddingTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  scaleModSize = 35;
        uint32_t        multDepth    = 13;
        if (bound == 16) multDepth += 4;

        vector<double>  timeEval(iteration);

        printBenchHeader("EmbeddingTest", {
            {"bound",      to_string(bound)},
            {"numcode",    to_string(numcode)},
            {"outputDim",  to_string(outputdimension)},
            {"iter",       to_string(iteration)},
            {"scaleMod",   to_string(scaleModSize)},
            {"multDepth",  to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize);
        auto cc   = ctx.cc;
        auto keys = ctx.keys;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<vector<double>>       inputVecs(numcode);
        for (usint s = 0; s < numcode; s++) inputVecs[s] = randomIntArray(batchSize, bound);

        CompressedEmbedding          model(numcode, bound, outputdimension);
        vector<double>               table = model.weight;

        vector<Ciphertext<DCRTPoly>> inputCts(numcode);
        for (usint s = 0; s < numcode; s++) {
            Plaintext segPt = cc->MakeCKKSPackedPlaintext(inputVecs[s]);
            inputCts[s]     = cc->Encrypt(keys.publicKey, segPt);
        }

        //─── 4. Timed evaluation ────────────────────────────────────────────
        vector<Ciphertext<DCRTPoly>> resultCts;
        Plaintext                    resultPt;
        vector<double>               expectedVec(batchSize);
        usint                        worstPrec = scaleModSize;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCts   = CodedHELUT(inputCts, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);

            for (usint d = 0; d < outputdimension; d++) {
                cc->Decrypt(keys.secretKey, resultCts[d], &resultPt);
                for (usint k = 0; k < batchSize; k++) {
                    expectedVec[k] = 0;
                    for (usint s = 0; s < numcode; s++) {
                        usint base      = s * bound + bound * numcode * d;
                        expectedVec[k] += table[base + (usint) inputVecs[s][k]];
                    }
                }
                usint dimPrec = precisionMute(resultPt, expectedVec, batchSize, 1);
                if (dimPrec < worstPrec) worstPrec = dimPrec;
            }
            cout << "  iter " << i << ": " << timeEval[i]
                 << " ms, worst-dim precision=" << worstPrec << " bits" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cout << "Estimated level: " << resultPt->GetLevel() << endl;
        cout << "Total: "; statTime(timeEval, iteration);
    }

    // HELUT Table 2 — SIMD-packed CodedHELUT on real CompressedEmbedding. Uses
    // CodedHELUT_P1 (§4.3 p1 parallelization) so multiple words pack per
    // ciphertext at stride bound*numcode.
    void EmbeddingSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  scaleModSize = 35;
        uint32_t        multDepth    = 13;
        if (bound == 16) multDepth += 4;
        const usint     stride       = bound * numcode;
        const usint     packedSlots  = batchSize / stride;

        vector<double>  timeEval(iteration);

        printBenchHeader("EmbeddingSIMDTest", {
            {"bound",      to_string(bound)},
            {"numcode",    to_string(numcode)},
            {"outputDim",  to_string(outputdimension)},
            {"iter",       to_string(iteration)},
            {"scaleMod",   to_string(scaleModSize)},
            {"multDepth",  to_string(multDepth)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize);
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForEmb(keys.secretKey, cc, stride);

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = randomIntArray(batchSize / bound, bound);
        CompressedEmbedding   model(numcode, bound, outputdimension);
        vector<double>        table    = model.weight;
        auto                  inputCts = EncryptForSIMD(inputVec, bound, keys.publicKey, cc);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        vector<Ciphertext<DCRTPoly>> resultCts;
        Plaintext                    resultPt;
        vector<double>               expectedVec(packedSlots);
        usint                        worstPrec = scaleModSize;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCts   = CodedHELUT_P1(inputCts, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);

            for (usint d = 0; d < outputdimension; d++) {
                cc->Decrypt(keys.secretKey, resultCts[d], &resultPt);
                for (usint k = 0; k < packedSlots; k++) {
                    expectedVec[k] = 0;
                    for (usint s = 0; s < numcode; s++) {
                        usint base      = s * bound + bound * numcode * d;
                        expectedVec[k] += table[base + (usint) inputVec[k * numcode + s]];
                    }
                }
                usint dimPrec = precisionMute(resultPt, expectedVec, packedSlots, stride);
                if (dimPrec < worstPrec) worstPrec = dimPrec;
            }
            cout << "  iter " << i << ": " << timeEval[i]
                 << " ms, worst-dim precision=" << worstPrec << " bits" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cout << "Estimated level: " << resultPt->GetLevel() << endl;
        cout << "Total: "; statTime(timeEval, iteration);
    }

    // HELUT Table 2 — sweep CodedHELUT (non-SIMD) over the three embedding dims
    // × five codebook configs from the paper.
    void EmbeddingTests(const usint iteration) {
        const vector<usint> outputDims = {50, 300, 768};
        const vector<usint> numcodes   = {8, 16, 32, 64, 32};
        const vector<usint> bounds     = {8,  8,  8,  8, 16};

        for (usint d = 0; d < outputDims.size(); d++) {
            for (usint c = 0; c < numcodes.size(); c++) {
                EmbeddingTest(bounds[c], numcodes[c], outputDims[d], iteration);
            }
        }
    }

    // HELUT Table 2 — sweep CodedHELUT (SIMD variant, what main_helut dispatches).
    void EmbeddingSIMDTests(const usint iteration) {
        const vector<usint> outputDims = {50, 300, 768};
        const vector<usint> numcodes   = {8, 16, 32, 64, 32};
        const vector<usint> bounds     = {8,  8,  8,  8, 16};

        for (usint d = 0; d < outputDims.size(); d++) {
            for (usint c = 0; c < numcodes.size(); c++) {
                EmbeddingSIMDTest(bounds[c], numcodes[c], outputDims[d], iteration);
            }
        }
    }


    // HELUT App. E.2 — SIMD-packed encrypted logistic-regression inference.
    // Pipeline: SIMD-encoded sentence ciphertexts → CodedHELUT_P1 (embedding
    // lookup) → InferenceEncryptedSIMD (logreg head) → decrypt + accuracy.
    // FIXME: the sentence batch index (2) and label batch index (0) are
    // mismatched in the original — predictions are scored against the wrong
    // labels. Marked but preserved for now to keep behavior identical.
    void LogregSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  scaleModSize = 35;
        const uint32_t  multDepth    = 40;
        const usint     sentLen      = 512;
        const usint     numpredicts  = batchSize / (bound * numcode * sentLen);

        vector<double>  timeLUT      (iteration);
        vector<double>  timeInference(iteration);
        vector<double>  timeEval     (iteration);

        printBenchHeader("LogregSIMDTest", {
            {"bound",      to_string(bound)},
            {"numcode",    to_string(numcode)},
            {"outputDim",  to_string(outputdimension)},
            {"iter",       to_string(iteration)},
            {"scaleMod",   to_string(scaleModSize)},
            {"multDepth",  to_string(multDepth)},
            {"sentLen",    to_string(sentLen)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForEmb(keys.secretKey, cc, batchSize);

        //─── 3. Inputs ──────────────────────────────────────────────────────
        // FIXME: batch index 2 for sentences vs. 0 for labels (mismatched in original).
        vector<string>      sentence = readsentence(sentLen, 2, 128);
        vector<usint>       answer   = readlabels  (         0, 128);

        CompressedEmbedding model (numcode, bound, outputdimension);
        LogregModel         logreg(numcode, bound, outputdimension);

        vector<usint>       lengthvec(numpredicts);
        for (usint p = 0; p < numpredicts; p++) {
            usint count = sentLen;
            for (usint w = 0; w < sentLen; w++) {
                if (sentence[sentLen * p + w] == "<pad>") count -= 1;
            }
            lengthvec[p] = count;
        }

        auto inputCts = EncryptSentenceSIMD(cc, keys.publicKey, sentence, model);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        vector<usint>  predict(numpredicts);
        usint          auc;
        Plaintext      resultPt;
        Ciphertext<DCRTPoly>            inferenceCt;

        for (usint i = 0; i < iteration; i++) {
            auc = 0;

            TIC(t);
            auto lutCts        = CodedHELUT_P1(inputCts, model.weight, bound, numcode, outputdimension);
            timeLUT[i]         = TOC(t);

            TIC(t);
            inferenceCt        = InferenceEncryptedSIMD(lutCts, sentLen, lengthvec, model, logreg);
            timeInference[i]   = TOC(t);

            timeEval[i] = timeLUT[i] + timeInference[i];

            cc->Decrypt(keys.secretKey, inferenceCt, &resultPt);
            vector<double> resVec = resultPt->GetRealPackedValue();

            for (usint p = 0; p < numpredicts; p++) {
                usint slot = bound * numcode * sentLen * p;
                predict[p] = (resVec[slot] > 0.5) ? 1 : 0;
                if (predict[p] == answer[p]) auc += 1;
            }
            cout << "  iter " << i << ": LUT=" << timeLUT[i] << "ms, Inf="
                 << timeInference[i] << "ms, accuracy=" << auc << "/" << numpredicts << endl;
        }

        //─── 5. Summary ─────────────────────────────────────────────────────
        cout << "LUT:        "; statTime(timeLUT,       iteration);
        cout << "Inference:  "; statTime(timeInference, iteration);
        cout << "Total:      "; statTime(timeEval,      iteration);
    }

    // HELUT App. E.2 — Sweep encrypted logreg (SIMD variant) over the same
    // (outputDim × codebook) grid as EmbeddingSIMDTests, minus the 768-dim row.
    void LogregSIMDTests(const usint iteration) {
        const vector<usint> outputDims = {50, 300};
        const vector<usint> numcodes   = {8, 16, 32, 64, 32};
        const vector<usint> bounds     = {8,  8,  8,  8, 16};

        for (usint d = 0; d < outputDims.size(); d++) {
            for (usint c = 0; c < numcodes.size(); c++) {
                LogregSIMDTest(bounds[c], numcodes[c], outputDims[d], iteration);
            }
        }
    }


    // HELUT App. E.2 — Non-SIMD encrypted logreg. Uses plaintext sentence
    // embeddings (SentenceEmbeddingPlain) re-encrypted directly, then
    // InferenceEncrypted for the logreg head. Iteration index `i` selects the
    // sentence batch (so each iteration scores a different 128-doc batch).
    // Writes per-iteration accuracy + max-error vs InferencePlain to
    // `logreg_result.txt` (resumable — see LogregTests).
    void LogregTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  scaleModSize = 35;
        uint32_t        multDepth    = 13;
        if (bound == 16) multDepth += 4;
        const usint     sentLen      = 512;
        const usint     numpredicts  = batchSize / sentLen;

        vector<double>  timeInference(iteration);
        vector<string>  resultlog(iteration + 2);
        resultlog[0] = "Test on bound: " + to_string(bound) +
                       ", number of codes: " + to_string(numcode) +
                       " , output dimension : " + to_string(outputdimension);

        printBenchHeader("LogregTest", {
            {"bound",      to_string(bound)},
            {"numcode",    to_string(numcode)},
            {"outputDim",  to_string(outputdimension)},
            {"iter",       to_string(iteration)},
            {"scaleMod",   to_string(scaleModSize)},
            {"multDepth",  to_string(multDepth)},
            {"sentLen",    to_string(sentLen)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;
        AddRotKeyForEmb(keys.secretKey, cc, sentLen);

        //─── 3. Models (data-resident) ──────────────────────────────────────
        CompressedEmbedding model (numcode, bound, outputdimension);
        LogregModel         logreg(numcode, bound, outputdimension);

        //─── 4. Per-iteration evaluation (each iter = fresh sentence batch) ─
        usint  totalAuc = 0;
        double maxError = 0.0;

        for (usint i = 0; i < iteration; i++) {
            vector<string> sentence = readsentence(sentLen, i, 128);
            vector<usint>  answer   = readlabels  (         i, 128);

            vector<usint> lengthvec(numpredicts);
            for (usint p = 0; p < numpredicts; p++) {
                usint count = sentLen;
                for (usint w = 0; w < sentLen; w++) {
                    const string &tok = sentence[sentLen * p + w];
                    if (tok == "<pad>" || tok == "<unk>") count -= 1;
                }
                lengthvec[p] = count;
            }

            // Plaintext embeddings → re-encrypted as ciphertexts (skips the LUT phase).
            vector<vector<double>>       emb = SentenceEmbeddingPlain(cc, sentence, model);
            vector<Ciphertext<DCRTPoly>> embCts(model.outputdimension);
            for (usint d = 0; d < model.outputdimension; d++) {
                Plaintext embPt = cc->MakeCKKSPackedPlaintext(emb[d]);
                embCts[d]       = cc->Encrypt(keys.publicKey, embPt);
            }

            TIC(t);
            Ciphertext<DCRTPoly> inferenceCt = InferenceEncrypted(embCts, sentLen, lengthvec, model, logreg);
            timeInference[i] = TOC(t);

            Plaintext              resultPt;
            cc->Decrypt(keys.secretKey, inferenceCt, &resultPt);
            vector<double>         resVec     = resultPt->GetRealPackedValue();
            vector<double>         predictVal = InferencePlain(cc, emb, sentLen, lengthvec, model, logreg);

            usint auc = 0;
            for (usint p = 0; p < numpredicts; p++) {
                usint pred = (resVec[sentLen * p] > 0) ? 1 : 0;
                if (pred == answer[p]) auc += 1;

                double gap = predictVal[p] - resVec[sentLen * p];
                if (gap < 0) gap = -gap;
                if (gap > maxError) maxError = gap;
            }
            totalAuc += auc;

            cout << "  iter " << i << ": Inf=" << timeInference[i]
                 << " ms, accuracy=" << auc << "/" << numpredicts
                 << ", maxError=" << maxError << endl;
            resultlog[i + 1] = to_string(timeInference[i]) +
                               "Estimated accuracy:" + to_string(auc) +
                               " per " + to_string(numpredicts) +
                               ", Maxerror: " + to_string(maxError);
        }

        //─── 5. Summary + log ───────────────────────────────────────────────
        cout << "Inference: ";
        string st = statTime(timeInference, iteration);
        cout << "Estimated accuracy: " << (double) totalAuc / (double)(numpredicts * iteration)
             << ", maxError=" << maxError
             << ", precision (bits)=" << -log2(maxError) << endl;
        resultlog[iteration + 1] = st +
            "Estimated accuracy:" + to_string((double) totalAuc / (double)(numpredicts * iteration)) +
            ", maxerror: " + to_string(maxError) +
            ", " + to_string(-log2(maxError));

        addRes(resultlog, "logreg_result.txt", iteration);
    }

    // HELUT App. E.2 — Sweep non-SIMD encrypted logreg. Resumable: skip any
    // config whose result block already exists in `logreg_result.txt`
    // (each block = iteration + 2 lines, so completion is detected by line count).
    void LogregTests(const usint iteration) {
        const vector<usint> outputDims = {50, 300};
        const vector<usint> numcodes   = {8, 16, 32, 64, 32};
        const vector<usint> bounds     = {8,  8,  8,  8, 16};
        const usint         blockLines = iteration + 2;

        for (usint d = 0; d < outputDims.size(); d++) {
            for (usint c = 0; c < numcodes.size(); c++) {
                usint completed = (d * numcodes.size()) + c + 1;
                if (checkline("logreg_result.txt") < blockLines * completed) {
                    LogregTest(bounds[c], numcodes[c], outputDims[d], iteration);
                }
            }
        }
    }

    // HELUT App. E.2 — Plaintext baseline for LogregTest. No CKKS work; runs
    // SentenceEmbeddingPlain + InferencePlain only. The CryptoContext is built
    // so the helpers accept it but PKE / KEYSWITCH / LEVELEDSHE are never
    // enabled and no keys are generated.
    // Note: the original surrounded zero work with TIC/TOC, so `timeInference`
    // captures only the overhead of two TimeVar calls. Preserved (~0 ms).
    void LogregTestPlain(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  scaleModSize = 35;
        uint32_t        multDepth    = 13;
        if (bound == 16) multDepth += 4;
        const usint     sentLen      = 512;
        const usint     numpredicts  = batchSize / sentLen;

        vector<double>  timeInference(iteration);
        vector<string>  resultlog(iteration + 2);
        resultlog[0] = "Test on bound: " + to_string(bound) +
                       ", number of codes: " + to_string(numcode) +
                       " , output dimension : " + to_string(outputdimension);

        printBenchHeader("LogregTestPlain", {
            {"bound",      to_string(bound)},
            {"numcode",    to_string(numcode)},
            {"outputDim",  to_string(outputdimension)},
            {"iter",       to_string(iteration)},
            {"sentLen",    to_string(sentLen)},
        });

        //─── 2. CKKS context (parameters only — no Enable, no KeyGen) ───────
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        //─── 3. Models (data-resident) ──────────────────────────────────────
        CompressedEmbedding model (numcode, bound, outputdimension);
        LogregModel         logreg(numcode, bound, outputdimension);

        //─── 4. Per-iteration plaintext inference ───────────────────────────
        usint  totalAuc = 0;
        double maxError = 0.0;

        for (usint i = 0; i < iteration; i++) {
            vector<string> sentence = readsentence(sentLen, i, 128);
            vector<usint>  answer   = readlabels  (         i, 128);

            vector<usint> lengthvec(numpredicts);
            for (usint p = 0; p < numpredicts; p++) {
                usint count = sentLen;
                for (usint w = 0; w < sentLen; w++) {
                    const string &tok = sentence[sentLen * p + w];
                    if (tok == "<pad>" || tok == "<unk>") count -= 1;
                }
                lengthvec[p] = count;
            }

            vector<vector<double>> emb = SentenceEmbeddingPlain(cc, sentence, model);

            TIC(t);
            // (No work timed — original behavior preserved.)
            timeInference[i] = TOC(t);

            vector<double> predictVal = InferencePlain(cc, emb, sentLen, lengthvec, model, logreg);

            usint auc = 0;
            for (usint p = 0; p < numpredicts; p++) {
                usint pred = (predictVal[p] > 0) ? 1 : 0;
                if (pred == answer[p]) auc += 1;
            }
            totalAuc += auc;

            cout << "  iter " << i << ": accuracy=" << auc << "/" << numpredicts << endl;
            resultlog[i + 1] = to_string(timeInference[i]) +
                               "Estimated accuracy:" + to_string(auc) +
                               " per " + to_string(numpredicts) +
                               ", Maxerror: " + to_string(maxError);
        }

        //─── 5. Summary + log ───────────────────────────────────────────────
        cout << "Inference: ";
        string st = statTime(timeInference, iteration);
        cout << "Estimated accuracy: " << (double) totalAuc / (double)(numpredicts * iteration) << endl;
        resultlog[iteration + 1] = st +
            "Estimated accuracy:" + to_string((double) totalAuc / (double)(numpredicts * iteration)) +
            ", maxerror: " + to_string(maxError) +
            ", " + to_string(-log2(maxError));

        addRes(resultlog, "logreg_result_plain.txt", iteration);
    }

    // HELUT App. E.2 — Sweep plaintext logreg baseline. Resumable, same skip
    // strategy as LogregTests against `logreg_result_plain.txt`.
    void LogregTestsPlain(const usint iteration) {
        const vector<usint> outputDims = {50, 300};
        const vector<usint> numcodes   = {8, 16, 32, 64, 32};
        const vector<usint> bounds     = {8,  8,  8,  8, 16};
        const usint         blockLines = iteration + 2;

        for (usint d = 0; d < outputDims.size(); d++) {
            for (usint c = 0; c < numcodes.size(); c++) {
                usint completed = (d * numcodes.size()) + c + 1;
                if (checkline("logreg_result_plain.txt") < blockLines * completed) {
                    LogregTestPlain(bounds[c], numcodes[c], outputDims[d], iteration);
                }
            }
        }
    }


} // namespace ckkseif
