#include "openfhe.h"
#include "test_core.h"
#include "algorithms.h"
#include "utils.h"
#include "bench_runner.h"

#include <omp.h>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

    // Shared infrastructure — CKKS bootstrap micro-benchmark with sparse-ternary
    // secret keys and `levelBudgetElmt`-deep linear/inverse FFT level budgets.
    // Not tied to any specific paper algorithm; used as a sanity check / sandbox
    // for tuning bootstrap parameters that downstream PrivTopk experiments rely on.
    void bootTest(const uint32_t scaleModSize, usint logbatchSize, usint levelBudgetElmt, usint iteration, usint /*precparam*/) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << logbatchSize;
        const uint32_t  multDepth = 2320 / scaleModSize;
        const int32_t   inputBound = 16;

        vector<double>  timeEval(iteration);

        printBenchHeader("bootTest", {
            {"scaleMod",      to_string(scaleModSize)},
            {"logbatchSize",  to_string(logbatchSize)},
            {"levelBudget",   to_string(levelBudgetElmt)},
            {"iter",          to_string(iteration)},
            {"multDepth",     to_string(multDepth)},
        });

        //─── 2. CKKS context + keys (with bootstrap setup) ──────────────────
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(SPARSE_TERNARY);
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        parameters.SetFirstModSize(scaleModSize + 1);
        cout << "Scaling Tech: " << parameters.GetScalingTechnique() << endl;

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(FHE);

        vector<uint32_t> levelBudget = {levelBudgetElmt, levelBudgetElmt};
        paramcheck(cc);
        usint bootDepth = FHECKKSRNS::GetBootstrapDepth(levelBudget, parameters.GetSecretKeyDist());
        cout << "bootDepth=" << bootDepth
             << ", budgetForCompute=" << multDepth - bootDepth << endl;

        KeyPair<DCRTPoly> keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        TIC(t);
        cc->EvalBootstrapSetup(levelBudget);
        cc->EvalBootstrapKeyGen(keys.secretKey, batchSize);
        cout << "Boot keygen: " << TOC(t) << " ms" << endl;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>  inputVec = randomIntArray(batchSize, inputBound);
        inputVec[0] = static_cast<double>(inputBound);

        Plaintext            inputPt = cc->MakeCKKSPackedPlaintext(inputVec, 1, bootDepth + 10);
        Ciphertext<DCRTPoly> inputCt = cc->Encrypt(keys.publicKey, inputPt);
        cout << "Ciphertext level pre-boot: " << inputCt->GetLevel() << endl;

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Ciphertext<DCRTPoly> resultCt;
        Plaintext            resultPt;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCt    = cc->EvalBootstrap(inputCt, 2, 10);
            timeEval[i] = TOC(t);
            cout << "  iter " << i << ": " << timeEval[i] << " ms" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cc->Decrypt(keys.secretKey, resultCt, &resultPt);
        precision(resultPt, inputVec, batchSize);
        resultPt->SetLength(8);
        cout << "Result: " << resultPt
             << ", post-boot level=" << resultCt->GetLevel() << endl;

        cout << "Total: "; statTime(timeEval, iteration);
    }

    // Shared infrastructure — alternate bootstrap configuration derived from
    // the OpenFHE example template (UNIFORM_TERNARY secret keys, smaller ring
    // dim, 8-slot fixed input). Single-shot smoke test of a depleted-ciphertext
    // bootstrap. No iteration parameter.
    void bootTest2() {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar               t;
        const SecretKeyDist   secretKeyDist = UNIFORM_TERNARY;

    #if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
        const ScalingTechnique rescaleTech = FIXEDAUTO;
        const usint            dcrtBits    = 78;
        const usint            firstMod    = 89;
    #else
        const ScalingTechnique rescaleTech = FLEXIBLEAUTO;
        const usint            dcrtBits    = 59;
        const usint            firstMod    = 60;
    #endif

        const vector<uint32_t> levelBudget                  = {2, 2};
        const uint32_t         levelsAvailableAfterBootstrap = 13;
        const usint            depth = levelsAvailableAfterBootstrap +
                                       FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);

        printBenchHeader("bootTest2", {
            {"secretKey", "UNIFORM_TERNARY"},
            {"ringDim",   to_string(1 << 15)},
            {"dcrtBits",  to_string(dcrtBits)},
            {"depth",     to_string(depth)},
        });

        //─── 2. CKKS context + keys (with bootstrap setup) ──────────────────
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(secretKeyDist);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 15);
        parameters.SetScalingModSize(dcrtBits);
        parameters.SetScalingTechnique(rescaleTech);
        parameters.SetFirstModSize(firstMod);
        parameters.SetNumLargeDigits(3);
        parameters.SetKeySwitchTechnique(HYBRID);
        parameters.SetMultiplicativeDepth(depth);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(FHE);

        const usint ringDim  = cc->GetRingDimension();
        const usint numSlots = ringDim / 2;
        cout << "ringDim=" << ringDim << ", numSlots=" << numSlots << endl;

        cc->EvalBootstrapSetup(levelBudget);
        KeyPair<DCRTPoly> keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        TIC(t);
        cc->EvalBootstrapKeyGen(keys.secretKey, numSlots);
        cout << "Boot keygen: " << TOC(t) << " ms" << endl;

        //─── 3. Inputs (depleted ciphertext to force bootstrap) ─────────────
        vector<double>  inputVec = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
        Plaintext       inputPt  = cc->MakeCKKSPackedPlaintext(inputVec, 1, depth - 1);
        inputPt->SetLength(inputVec.size());
        cout << "Input: " << inputPt << endl;

        Ciphertext<DCRTPoly> inputCt = cc->Encrypt(keys.publicKey, inputPt);
        cout << "Levels remaining pre-boot: " << depth - inputCt->GetLevel() << endl;

        //─── 4. Timed evaluation ────────────────────────────────────────────
        TIC(t);
        Ciphertext<DCRTPoly> resultCt = cc->EvalBootstrap(inputCt);
        double               timeEval = TOC(t);
        cout << "Bootstrap time: " << timeEval << " ms" << endl;

        //─── 5. Validation ──────────────────────────────────────────────────
        cout << "Levels remaining post-boot: "
             << depth - resultCt->GetLevel() - (resultCt->GetNoiseScaleDeg() - 1) << endl;

        Plaintext resultPt;
        cc->Decrypt(keys.secretKey, resultCt, &resultPt);
        precision(resultPt, inputVec, 8);
        resultPt->SetLength(inputVec.size());
        cout << "Output: " << resultPt << endl;
    }



    // Shared infrastructure — `EvalLog` micro-benchmark. Inputs are drawn from
    // [1, 1 + bound] (the +1 shift puts them in the log-power-series region).
    void logTest(const double bound, const usint degree, const usint iteration, const uint32_t scaleModSize) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 25;

        vector<double>  timeEval(iteration);

        printBenchHeader("logTest", {
            {"bound",     to_string(bound)},
            {"degree",    to_string(degree)},
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

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double> inputVec = randomRealArray(batchSize, bound);
        for (usint i = 0; i < batchSize; i++) inputVec[i] += 1;     // shift into [1, 1+bound]

        vector<double> expectedVec(batchSize);
        for (usint i = 0; i < batchSize; i++) expectedVec[i] = log(inputVec[i]);

        cout << "First 8 expected log values: ";
        for (usint i = 0; i < 8; i++) cout << expectedVec[i] << ", ";
        cout << endl;

        Plaintext             inputPt = cc->MakeCKKSPackedPlaintext(inputVec);
        Ciphertext<DCRTPoly>  inputCt = cc->Encrypt(keys.publicKey, inputPt);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Ciphertext<DCRTPoly>  resultCt;
        Plaintext             resultPt;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCt    = EvalLog(inputCt, bound, 0, degree);
            timeEval[i] = TOC(t);

            cc->Decrypt(keys.secretKey, resultCt, &resultPt);
            precision(resultPt, expectedVec, batchSize);
            resultPt->SetLength(8);
            cout << "  iter " << i << ": " << timeEval[i] << " ms, result=" << resultPt << endl;
        }

        //─── 5. Summary ─────────────────────────────────────────────────────
        cout << "Estimated level: " << resultPt->GetLevel() << endl;
        cout << "Total: "; statTime(timeEval, iteration);
    }

    // HELUT §3.3 / Eq. 7 — EEF benchmark: Indicator = Cleanse ∘ SqMethod over bound-many residues.
    void EEFTest(const usint bound, const usint iteration, const uint32_t scaleModSize) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize    = 1u << 16;
        uint32_t        multDepth    = 25;
        if (bound >  256) multDepth += 5;
        if (bound > 1024) multDepth += 5;

        vector<double>  timeEval(iteration);
        vector<double>  timeSqMethod(iteration);
        vector<double>  timeCleanse(iteration);

        printBenchHeader("EEFTest", {
            {"bound",        to_string(bound)},
            {"iter",         to_string(iteration)},
            {"scaleMod",     to_string(scaleModSize)},
            {"multDepth",    to_string(multDepth)},
            {"batchSize",    to_string(batchSize)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize);
        auto cc   = ctx.cc;
        auto keys = ctx.keys;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = randomIntArray(batchSize, bound);
        inputVec[0] = 0.0;     // guarantee at least one zero so the indicator's hit case is exercised

        Plaintext             inputPt  = cc->MakeCKKSPackedPlaintext(inputVec);
        Ciphertext<DCRTPoly>  inputCt  = cc->Encrypt(keys.publicKey, inputPt);

        vector<usint> rounds    = ParamEEF(bound, scaleModSize);
        const usint   cleanIter = rounds[1];
        rounds[1] = 0;     // run Cleanse manually after timing SqMethod
        cout << "Rounds: " << rounds << ", cleanseRounds: " << cleanIter << endl;

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Ciphertext<DCRTPoly>  sqCt;
        Ciphertext<DCRTPoly>  cleansedCt;
        Plaintext             resultPt;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            sqCt            = EEF(inputCt, bound, rounds, 0);
            timeSqMethod[i] = TOC(t);

            cleansedCt      = Cleanse(sqCt, cleanIter);
            timeEval[i]     = TOC(t);
            timeCleanse[i]  = timeEval[i] - timeSqMethod[i];

            cout << "  iter " << i << ": total=" << timeEval[i]
                 << " ms (SqMethod=" << timeSqMethod[i]
                 << ", Cleanse=" << timeCleanse[i] << ")" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cc->Decrypt(keys.secretKey, sqCt,       &resultPt);
        binaryprecision(resultPt, batchSize);
        cc->Decrypt(keys.secretKey, cleansedCt, &resultPt);
        binaryprecision(resultPt, batchSize);
        cout << "Estimated level: " << resultPt->GetLevel() << endl;

        cout << "Total:    "; statTime(timeEval,     iteration);
        cout << "SqMethod: "; statTime(timeSqMethod, iteration);
        cout << "Cleanse:  "; statTime(timeCleanse,  iteration);
    }

    void EEFSIMDTest(const usint bound, const usint iteration, const uint32_t scaleModSize) {
        TimeVar t;
        vector<double> timeEval(iteration);
        vector<double> timeSq(iteration);
        vector<double> timeCleanse(iteration);

        uint32_t multDepth = 25;
        if(bound > 256)multDepth+=5;
        uint32_t batchSize = 1 << 16;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        //cout << "CKKS standard deviation " << parameters.GetStandardDeviation() << endl;
        //cout << "CKKS security level " <<  parameters.GetSecurityLevel() << endl;

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;
        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! INDICATOR Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << std::endl;

        // Inputs
        std::vector<double> x1 = randomIntArray(batchSize, bound);
        x1[0]=0.0;
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        //std::cout << "\n Input x1: " << ptxt1 << std::endl;

        // Encrypt the encoded vectors
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;
        Plaintext numtocheck = GenEEFChecker(bound, cc);
        vector<usint> rounds=ParamEEF(bound, scaleModSize);
        cout << "Rounds: " << rounds << endl;
        usint cleaniter=rounds[1];
        rounds[1]=0;
        Ciphertext<DCRTPoly> c2;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            // if(bound==2){
            //     c2=cc->EvalAdd(c1, 0.001);
            //     c2=EEFBinary(c2,rounds);
            // }else{
            c2 = EEFSIMD(c1, bound, rounds, numtocheck);
            // }
            timeSq[i] = TOC(t);
            auto c3 = Cleanse(c2, cleaniter);
            timeEval[i] = TOC(t);
            timeCleanse[i]=timeEval[i]-timeSq[i];
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            cc->Decrypt(keys.secretKey, c2, &result);
            binaryprecision(result, batchSize);
            cc->Decrypt(keys.secretKey, c3, &result);
            binaryprecision(result, batchSize);
            result->SetLength(8);
            std::cout.precision(8);
            //std::cout << "result = " << result << endl;
            if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        std::cout << "Total: ";
        statTime(timeEval, iteration);
        std::cout << "Square: ";
        statTime(timeSq, iteration);
        std::cout << "Cleanse: ";
        statTime(timeCleanse, iteration);


    } 

    // HELUT App. E.4 — EEF baseline at fixed multDepth=30 (used by AnotherIndicatorTests).
    // Specializes to EEFBinary when p=2 (HELUT §3.3 binary case).
    void EEFTestDepth30(const usint bound, const usint iteration, const uint32_t scaleModSize) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 30;

        vector<double>  timeEval(iteration);
        vector<double>  timeSqMethod(iteration);
        vector<double>  timeCleanse(iteration);

        printBenchHeader("EEFTestDepth30", {
            {"bound",     to_string(bound)},
            {"iter",      to_string(iteration)},
            {"scaleMod",  to_string(scaleModSize)},
            {"multDepth", to_string(multDepth)},
            {"batchSize", to_string(batchSize)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize);
        auto cc   = ctx.cc;
        auto keys = ctx.keys;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = randomIntArray(batchSize, bound);
        inputVec[0] = 0.0;

        Plaintext             inputPt = cc->MakeCKKSPackedPlaintext(inputVec);
        Ciphertext<DCRTPoly>  inputCt = cc->Encrypt(keys.publicKey, inputPt);

        vector<usint> rounds    = ParamEEF(bound, scaleModSize);
        const usint   cleanIter = rounds[1];
        rounds[1] = 0;
        cout << "Rounds: " << rounds << ", cleanseRounds: " << cleanIter << endl;

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Ciphertext<DCRTPoly>  sqCt;
        Ciphertext<DCRTPoly>  cleansedCt;
        Plaintext             resultPt;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            if (bound == 2) {
                sqCt = cc->EvalAdd(inputCt, 0.001);
                sqCt = EEFBinary(sqCt, rounds);
            } else {
                sqCt = EEF(inputCt, bound, rounds, 0);
            }
            timeSqMethod[i] = TOC(t);

            cleansedCt     = Cleanse(sqCt, cleanIter);
            timeEval[i]    = TOC(t);
            timeCleanse[i] = timeEval[i] - timeSqMethod[i];

            cout << "  iter " << i << ": total=" << timeEval[i]
                 << " ms (SqMethod=" << timeSqMethod[i]
                 << ", Cleanse=" << timeCleanse[i] << ")" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cc->Decrypt(keys.secretKey, sqCt,       &resultPt);
        binaryprecision(resultPt, batchSize);
        cc->Decrypt(keys.secretKey, cleansedCt, &resultPt);
        binaryprecision(resultPt, batchSize);
        cout << "Estimated level: " << resultPt->GetLevel() << endl;

        cout << "Total:    "; statTime(timeEval,     iteration);
        cout << "SqMethod: "; statTime(timeSqMethod, iteration);
        cout << "Cleanse:  "; statTime(timeCleanse,  iteration);
    }

    // HELUT §3 — Sweep EEFTest over bounds 2^2..2^{6 or 8} depending on scaleModSize budget.
    void EEFTests(const usint iteration, uint32_t scaleModSize) {
        const usint boundBitsMax = (scaleModSize > 35) ? 9 : 7;
        for (usint boundBits = 2; boundBits < boundBitsMax; boundBits++) {
            EEFTest(1u << boundBits, iteration, scaleModSize);
        }
    }


    // HELUT App. E.4 / §D.3.1 — Compare the four EIF baselines (Lagrange, Comparison,
    // Sinc, Depth-30 EEF) at log Δ ∈ {35, 50} and log p ∈ {3, 6, 10}. Lagrange is
    // only run at log p = 3 since higher p makes the interpolating polynomial intractable.
    void AnotherIndicatorTests(const usint iteration) {
        uint32_t sf = 35;
        IndicatorByLagrangeTest  (8,  iteration, sf);
        IndicatorByESFTest(8,  iteration, sf);
        IndicatorBySincTest      (3, 8, iteration, sf);
        EEFTestDepth30           (8,  iteration, sf);

        IndicatorByESFTest(64, iteration, sf);
        IndicatorBySincTest      (6, 8, iteration, sf);
        EEFTestDepth30           (64, iteration, sf);

        sf = 50;
        IndicatorByLagrangeTest  (8,  iteration, sf);
        IndicatorByESFTest(8,  iteration, sf);
        IndicatorBySincTest      (3, 8, iteration, sf);
        EEFTestDepth30           (8,  iteration, sf);

        IndicatorByESFTest(64, iteration, sf);
        IndicatorBySincTest      (6, 8, iteration, sf);
        EEFTestDepth30           (64, iteration, sf);

        IndicatorByESFTest(1024, iteration, sf);
        IndicatorBySincTest      (10, 8, iteration, sf);
        EEFTestDepth30           (1024, iteration, sf);
    }

    // HELUT App. E.4 / §D.3.1 — Sinc-based EIF baseline (Lee et al., HEaaN-Stat 2023).
    // d  = log₂(input bound).
    // K  = polynomial degree controlling the sinc approximation.
    void IndicatorBySincTest(const usint d, const usint K, const usint iteration, const uint32_t scaleModSize) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 30;
        const usint     bound     = 1u << d;

        vector<double>  timeEval(iteration);

        printBenchHeader("IndicatorBySincTest", {
            {"bound",     to_string(bound)},
            {"d",         to_string(d)},
            {"K",         to_string(K)},
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

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = randomIntArray(batchSize, bound);
        inputVec[0] = 0.0;

        Plaintext             inputPt = cc->MakeCKKSPackedPlaintext(inputVec);
        Ciphertext<DCRTPoly>  inputCt = cc->Encrypt(keys.publicKey, inputPt);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Ciphertext<DCRTPoly>  resultCt;
        Plaintext             resultPt;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCt    = IndicatorBySinc(inputCt, d, K);
            timeEval[i] = TOC(t);
            cout << "  iter " << i << ": total=" << timeEval[i] << " ms" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cc->Decrypt(keys.secretKey, resultCt, &resultPt);
        binaryprecision(resultPt, batchSize);
        cout << "Estimated level: " << resultPt->GetLevel() << endl;

        cout << "Total: "; statTime(timeEval, iteration);
    }


    // HELUT App. E.4 / §D.3.1 — Comparison-based EIF baseline (Cheon et al. 2020).
    // Implements 1{x == 0} ad hoc as ESF(x) composed with the polynomial 1 - x²
    // (i.e. EvalPoly with coefficients {1, 0, -1}). Inputs are fixedDiscreteArray
    // to mirror the original baseline's evaluation regime.
    void IndicatorByESFTest(const usint bound, const usint iteration, const uint32_t scaleModSize) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 30;

        vector<double>  timeEval(iteration);

        printBenchHeader("IndicatorByESFTest", {
            {"bound",     to_string(bound)},
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

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = fixedDiscreteArray(batchSize, bound);
        Plaintext             inputPt  = cc->MakeCKKSPackedPlaintext(inputVec);
        Ciphertext<DCRTPoly>  inputCt  = cc->Encrypt(keys.publicKey, inputPt);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Ciphertext<DCRTPoly>  resultCt;
        Plaintext             resultPt;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCt    = ESF(inputCt, static_cast<uint32_t>(bound), false, false);
            resultCt    = cc->EvalPoly(resultCt, {1, 0, -1});     // 1 - x²: turns sign into equality
            timeEval[i] = TOC(t);
            cout << "  iter " << i << ": total=" << timeEval[i] << " ms" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cc->Decrypt(keys.secretKey, resultCt, &resultPt);
        binaryprecision(resultPt, batchSize);
        cout << "Estimated level: " << resultPt->GetLevel() << endl;

        cout << "Total: "; statTime(timeEval, iteration);
    }


    // HELUT App. E.4 / §D.3.1 — Lagrange-interpolation EIF baseline (strawman).
    // Uses ParamSqMethod(bound) to obtain the Lagrange polynomial coefficients
    // that interpolate the indicator on the bound-many residues.
    void IndicatorByLagrangeTest(const usint bound, const usint iteration, const uint32_t scaleModSize) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 30;

        vector<double>  timeEval(iteration);

        printBenchHeader("IndicatorByLagrangeTest", {
            {"bound",     to_string(bound)},
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

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = randomIntArray(batchSize, bound);
        inputVec[0] = 0.0;

        Plaintext             inputPt = cc->MakeCKKSPackedPlaintext(inputVec);
        Ciphertext<DCRTPoly>  inputCt = cc->Encrypt(keys.publicKey, inputPt);

        const vector<double>  lagrangeCoeff = ParamSqMethod(bound);

        //─── 4. Timed evaluation ────────────────────────────────────────────
        Ciphertext<DCRTPoly>  resultCt;
        Plaintext             resultPt;

        for (usint i = 0; i < iteration; i++) {
            TIC(t);
            resultCt    = IndicatorByLagrange(inputCt, bound, lagrangeCoeff);
            timeEval[i] = TOC(t);
            cout << "  iter " << i << ": total=" << timeEval[i] << " ms" << endl;
        }

        //─── 5. Validation + summary ────────────────────────────────────────
        cc->Decrypt(keys.secretKey, resultCt, &resultPt);
        binaryprecision(resultPt, batchSize);
        cout << "Estimated level: " << resultPt->GetLevel() << endl;

        cout << "Total: "; statTime(timeEval, iteration);
    }


    //----------------------------------------------------------------------------------
    //   Comparison & Sign Function Tests (used as building blocks by PrivTopk)
    //----------------------------------------------------------------------------------

    // PrivTopk §II-B — Encrypted Sign Function precision sweep over polynomial
    // schedules. Reports precision (in bits) for each (initial degg, refinement
    // passes) combination across the budget that `scaleModSize` allows. No
    // timing — this is an accuracy probe, not a benchmark.
    void ESFTests(const uint32_t scaleModSize, const uint32_t bound) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        const uint32_t  batchSize    = 1u << 16;
        const uint32_t  multDepth    = 2500 / scaleModSize;     // budget: 52 @ Δ=40, 59 @ Δ=35
        const double    inputBound   = 1.0;
        const uint32_t  esfVersion   = 3;

        printBenchHeader("ESFTests", {
            {"bound",     to_string(bound)},
            {"scaleMod",  to_string(scaleModSize)},
            {"multDepth", to_string(multDepth)},
            {"batchSize", to_string(batchSize)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = fixedDiscreteArray(batchSize, bound);
        Plaintext             inputPt  = cc->MakeCKKSPackedPlaintext(inputVec);
        Ciphertext<DCRTPoly>  inputCt  = cc->Encrypt(keys.publicKey, inputPt);

        cout << "First 8 inputs: ";
        for (usint i = 0; i < 8; i++) cout << inputVec[i] << ", ";
        cout << endl;
        cout.precision(4);

        //─── 4. Polynomial-schedule sweep ───────────────────────────────────
        // Outer: initial g-polynomial degree (no f component yet).
        // Inner: number of f-degree-1 refinement passes layered on top.
        Plaintext resultPt;

        for (uint32_t initDegG = 2; initDegG < 6; initDegG++) {
            Ciphertext<DCRTPoly> resultCt =
                EncryptedSignFunction(inputCt, /*degf=*/0, /*degg=*/initDegG, inputBound, esfVersion);
            cc->Decrypt(keys.secretKey, resultCt, &resultPt);

            cout << "----- initDegG=" << initDegG << " :: ";
            compprecision(resultCt, inputVec, batchSize, cc, keys);
            binaryprecision(resultPt, batchSize);
            resultPt->SetLength(8);
            cout << resultPt << endl;

            for (uint32_t refinePass = 1; refinePass < 4; refinePass++) {
                resultCt = EncryptedSignFunction(resultCt, /*degf=*/1, /*degg=*/0, inputBound, esfVersion);
                cc->Decrypt(keys.secretKey, resultCt, &resultPt);

                cout << "  refine=" << refinePass << ", initDegG=" << initDegG << " :: ";
                compprecision(resultCt, inputVec, batchSize, cc, keys);
                binaryprecision(resultPt, batchSize);
                resultPt->SetLength(8);
                cout << resultPt << ", level=" << resultPt->GetLevel() << endl;
            }
        }
    }


    // PrivTopk §II-B — Single-shot ESF probe (convenience wrapper, fixed depth
    // budget). Not currently dispatched from any main_*.cpp; useful as a quick
    // smoke test of ESF correctness at a particular (Δ, bound) point.
    void ESFTest(const uint32_t scaleModSize, const uint32_t bound) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 52;

        printBenchHeader("ESFTest", {
            {"bound",     to_string(bound)},
            {"scaleMod",  to_string(scaleModSize)},
            {"multDepth", to_string(multDepth)},
            {"batchSize", to_string(batchSize)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<double>        inputVec = fixedDiscreteArray(batchSize, bound);
        Plaintext             inputPt  = cc->MakeCKKSPackedPlaintext(inputVec);
        Ciphertext<DCRTPoly>  inputCt  = cc->Encrypt(keys.publicKey, inputPt);

        //─── 4. Evaluation ──────────────────────────────────────────────────
        Ciphertext<DCRTPoly> resultCt = ESF(inputCt, bound, false, false);
        Plaintext            resultPt;

        //─── 5. Validation ──────────────────────────────────────────────────
        cc->Decrypt(keys.secretKey, resultCt, &resultPt);
        binaryprecision(resultPt, batchSize);
        resultPt->SetLength(16);
        cout << resultPt << ", level=" << resultPt->GetLevel() << endl;
    }


    // PrivTopk §II-B / §V-B2 — Quantized arbitrary-precision ESF over a
    // multi-segment ciphertext (boundBits-bit signed value split into
    // ⌈boundBits / baseBits⌉ segments of baseBits each). Single-shot eval.
    void ESFQTest(const uint32_t scaleModSize, const uint32_t boundBits, const uint32_t baseBits) {

        //─── 1. Parameters ──────────────────────────────────────────────────
        TimeVar         t;
        const uint32_t  batchSize = 1u << 16;
        const uint32_t  multDepth = 2500 / scaleModSize;
        const uint32_t  segBound  = 1u << baseBits;
        const uint32_t  quantNum  = (boundBits + baseBits - 1) / baseBits;
        const bool      lastMod   = true;     // final shift-and-scale into [0, 1]

        printBenchHeader("ESFQTest", {
            {"boundBits", to_string(boundBits)},
            {"baseBits",  to_string(baseBits)},
            {"quantNum",  to_string(quantNum)},
            {"scaleMod",  to_string(scaleModSize)},
            {"multDepth", to_string(multDepth)},
            {"batchSize", to_string(batchSize)},
        });

        //─── 2. CKKS context + keys ─────────────────────────────────────────
        auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
                                    {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
                                     CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE,
                                     CKKSFeature::FHE});
        auto cc   = ctx.cc;
        auto keys = ctx.keys;

        //─── 3. Inputs ──────────────────────────────────────────────────────
        vector<Ciphertext<DCRTPoly>>  inputCts(quantNum);
        vector<double>                expectedSign(8);

        for (uint32_t seg = 0; seg < quantNum; seg++) {
            vector<double> segVec = randomDiscreteArray(batchSize, segBound);
            segVec[seg]     = 0.0;
            segVec[seg + 1] = -segVec[seg + 1];

            Plaintext segPt = cc->MakeCKKSPackedPlaintext(segVec);
            inputCts[seg]   = cc->Encrypt(keys.publicKey, segPt);

            // Expected sign of the combined multi-segment value (first 8 slots
            // only — locked-in at first non-zero segment).
            for (uint32_t j = 0; j < 8; j++) {
                if (expectedSign[j] == 0) {
                    if (segVec[j] > 0) expectedSign[j] =  1;
                    if (segVec[j] < 0) expectedSign[j] = -1;
                }
            }
        }

        // Map {-1, 0, 1} → {0, 0.5, 1} since lastMod composes a final scale step.
        if (lastMod) {
            for (uint32_t j = 0; j < 8; j++) expectedSign[j] = expectedSign[j] * 0.5 + 0.5;
        }

        //─── 4. Timed evaluation ────────────────────────────────────────────
        TIC(t);
        Ciphertext<DCRTPoly> resultCt = ESFQ(inputCts, segBound, lastMod, 45);
        double               timeEval = TOC(t);

        //─── 5. Validation + summary ────────────────────────────────────────
        Plaintext resultPt;
        cc->Decrypt(keys.secretKey, resultCt, &resultPt);
        binaryprecision(resultPt, batchSize);
        resultPt->SetLength(16);
        cout << resultPt << ", level=" << resultPt->GetLevel()
             << ", time=" << timeEval << " ms" << endl;
        cout << "Expected (first 8): " << expectedSign << endl;
        precision(resultPt, expectedSign, 8);
    }

} // namespace ckkseif
