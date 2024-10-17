#include "openfhe.h"
#include "testcode.h"
#include "embedding.h"
#include "algorithms.h"

using namespace lbcrypto;
using namespace std;

namespace ckkseif {


    void bootTest(const uint32_t scaleModSize, usint logbatchSize, usint ringdim) {

        TimeVar t;


        uint32_t multDepth = 2320/scaleModSize -10 ;
        uint32_t batchSize = 1 << logbatchSize;
        uint32_t numSlotsBoot= 1 << logbatchSize;
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(SPARSE_TERNARY);

        //parameters.SetSecretKeyDist(UNIFORM_TERNARY);
        parameters.SetSecurityLevel(HEStd_NotSet);


        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(1 << ringdim);
        parameters.SetBatchSize(batchSize);
        
        /// Bootstrap block 1 ////      

        //parameters.SetScalingTechnique(FLEXIBLEAUTO);
        parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);
        cout << "Scaling Tech: " << parameters.GetScalingTechnique() << endl;

        parameters.SetFirstModSize(scaleModSize+1);
        //parameters.SetFirstModSize(60);


        // parameters.SetNumLargeDigits(3);
        parameters.SetNumLargeDigits(0);
        parameters.SetKeySwitchTechnique(HYBRID);


        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        //std::cout << "Parameters " << parameters << std::endl << std::endl;


        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       
        //// bootblock2
        cc->Enable(FHE);
        // usint levelBudgetElmt= (logbatchSize >14 ) ? 1 << (logbatchSize-13) : 2 ;  
        usint levelBudgetElmt= (ringdim >15 ) ? 1 << (ringdim-14) : 2 ;  

        //usint levelBudgetElmt = 2;

        std::vector<uint32_t> levelBudget = {levelBudgetElmt, levelBudgetElmt};
        //cc->EvalBootstrapSetup(levelBudget);

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;


        paramcheck(cc);
        usint depth = FHECKKSRNS::GetBootstrapDepth(levelBudget, parameters.GetSecretKeyDist());
        cout << "scaleModSize: " << scaleModSize << endl;
        cout << "bootdepth: " << depth << ", levelBudget: " << levelBudgetElmt << endl;
        cout << "budgetdepth: " << multDepth-depth << endl;
        cout << "SlotDim: " << logbatchSize << endl;


        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);


        //uint32_t numSlotsBoot=batchSize;
        //uint32_t numSlotsBoot=128;
        TIC(t);
        // cc->EvalBootstrapSetup(levelBudget);
        // cout << "Boot Setup Done" << endl;
        // cc->EvalBootstrapKeyGen(keys.secretKey, batchSize);

        cc->EvalBootstrapSetup(levelBudget, {0,0}, numSlotsBoot);
        cout << "Boot Setup Done" << endl;
        cc->EvalBootstrapKeyGen(keys.secretKey, numSlotsBoot);
        double timeEval0 =TOC(t);
        cout<<"Boot Keygen Done: "<< timeEval0 << "ms" << endl;

        //bootSet2(cc, keys.secretKey, batchSize);


        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Boot Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        //std::vector<double> x1 = randomDiscreteArray(batchSize, 128);
        //x1[0]=0.1;
        // std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        std::vector<double> x1 = randomIntArray(batchSize, 2);

        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, multDepth - 1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, depth+1);


        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        //cc->LevelReduceInPlace(c1, nullptr, multDepth-1);
        cc->Decrypt(keys.secretKey, c1, &result);
        cout<<"level: " << c1->GetLevel() <<endl;
        TIC(t);
        //c1->SetSlots(numSlotsBoot);
        auto c2 = cc->EvalBootstrap(c1,1);
        double timeEval=TOC(t);
        cc->Decrypt(keys.secretKey, c2, &result);
        precision(result, x1, batchSize);
        result->SetLength(8);
        cout << result << " :: " << "\nEstimated level: " << c2->GetLevel() << ", Time: " << timeEval << std::endl;


        // TIC(t);
        // c2 = cc->EvalBootstrap(c1,2);
        // timeEval=TOC(t);
        // cc->Decrypt(keys.secretKey, c2, &result);
        // precision(result, x1, batchSize);
        // result->SetLength(8);
        // cout << result << " :: " << "\nEstimated level: " << c2->GetLevel() << ", Time: " << timeEval << std::endl;



    } 

    void bootTest2() {
        TimeVar t;
        CCParams<CryptoContextCKKSRNS> parameters;
        // A. Specify main parameters
        /*  A1) Secret key distribution
        * The secret key distribution for CKKS should either be SPARSE_TERNARY or UNIFORM_TERNARY.
        * The SPARSE_TERNARY distribution was used in the original CKKS paper,
        * but in this example, we use UNIFORM_TERNARY because this is included in the homomorphic
        * encryption standard.
        */
        SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
        parameters.SetSecretKeyDist(UNIFORM_TERNARY);

        /*  A2) Desired security level based on FHE standards.
        * In this example, we use the "NotSet" option, so the example can run more quickly with
        * a smaller ring dimension. Note that this should be used only in
        * non-production environments, or by experts who understand the security
        * implications of their choices. In production-like environments, we recommend using
        * HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
        * or 256-bit security, respectively. If you choose one of these as your security level,
        * you do not need to set the ring dimension.
        */
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 15);

        /*  A3) Scaling parameters.
        * By default, we set the modulus sizes and rescaling technique to the following values
        * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
        * below unless you are an FHE expert.
        */
    #if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
        ScalingTechnique rescaleTech = FIXEDAUTO;
        usint dcrtBits               = 78;
        usint firstMod               = 89;
    #else
        ScalingTechnique rescaleTech = FLEXIBLEAUTO;
        usint dcrtBits               = 59;
        usint firstMod               = 60;
    #endif

        cout << rescaleTech << ", " << firstMod << " , " << dcrtBits << endl;

        parameters.SetScalingModSize(dcrtBits);
        parameters.SetScalingTechnique(rescaleTech);
        parameters.SetFirstModSize(firstMod);


        parameters.SetNumLargeDigits(3);
        parameters.SetKeySwitchTechnique(HYBRID);

        /*  A4) Multiplicative depth.
        * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
        * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
        * needs to consume a few levels to run. We compute the number of bootstrapping levels required
        * using GetBootstrapDepth, and add it to levelsAvailableAfterBootstrap to set our initial multiplicative
        * depth. We recommend using the input parameters below to get started.
        */
        std::vector<uint32_t> levelBudget = {2, 2};

        // Note that the actual number of levels avalailable after bootstrapping before next bootstrapping 
        // will be levelsAvailableAfterBootstrap - 1 because an additional level
        // is used for scaling the ciphertext before next bootstrapping (in 64-bit CKKS bootstrapping)
        uint32_t levelsAvailableAfterBootstrap = 13;
        usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
        parameters.SetMultiplicativeDepth(depth);

        CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);
        cryptoContext->Enable(ADVANCEDSHE);
        cryptoContext->Enable(FHE);

        usint ringDim = cryptoContext->GetRingDimension();
        // This is the maximum number of slots that can be used for full packing.
        usint numSlots = ringDim / 2;
        std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;

        cryptoContext->EvalBootstrapSetup(levelBudget);

        auto keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);
        TIC(t);
        cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);
        auto timeEval=TOC(t);
        cout << "BootKeygen: " << timeEval << endl;
        std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
        size_t encodedLength  = x.size();

        // We start with a depleted ciphertext that has used up all of its levels.
        Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1);

        ptxt->SetLength(encodedLength);
        std::cout << "Input: " << ptxt << std::endl;

        Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

        std::cout << "Initial number of levels remaining: " << depth - ciph->GetLevel() << std::endl;

        // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
        // for HE computation.
        TIC(t);
        auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);
        timeEval=TOC(t);
        cout << "BootDone: " << timeEval << endl;

        std::cout << "Number of levels remaining after bootstrapping: "
                << depth - ciphertextAfter->GetLevel() - (ciphertextAfter->GetNoiseScaleDeg() - 1) << std::endl
                << std::endl;

        Plaintext result;
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
        precision(result,x,8);
        result->SetLength(encodedLength);
        std::cout << "Output after bootstrapping \n\t" << result << std::endl;
    }


    void binarybootTest(const uint32_t scaleModSize) {

        TimeVar t;


        uint32_t multDepth = 2320/scaleModSize -10 ;
        uint32_t batchSize = 1 << 16;
        // uint32_t numSlotsBoot= 1 << 16;
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(SPARSE_TERNARY);

        //parameters.SetSecretKeyDist(UNIFORM_TERNARY);
        parameters.SetSecurityLevel(HEStd_NotSet);


        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(1 << 17);
        parameters.SetBatchSize(batchSize);
        
        /// Bootstrap block 1 ////      

        //parameters.SetScalingTechnique(FLEXIBLEAUTO);
        parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);
        cout << "Scaling Tech: " << parameters.GetScalingTechnique() << endl;

        parameters.SetFirstModSize(scaleModSize+1);
        //parameters.SetFirstModSize(60);


        // parameters.SetNumLargeDigits(3);
        parameters.SetNumLargeDigits(0);
        parameters.SetKeySwitchTechnique(HYBRID);


        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        //std::cout << "Parameters " << parameters << std::endl << std::endl;


        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       
        //// bootblock2
        cc->Enable(FHE);
        // usint levelBudgetElmt= (logbatchSize >14 ) ? 1 << (logbatchSize-13) : 2 ;  
        // usint levelBudgetElmt= (ringdim >15 ) ? 1 << (ringdim-14) : 2 ;  

        usint levelBudgetElmt = 2;

        std::vector<uint32_t> levelBudget = {levelBudgetElmt, levelBudgetElmt};
        //cc->EvalBootstrapSetup(levelBudget);

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;


        paramcheck(cc);
        usint depth = FHECKKSRNS::GetBootstrapDepth(levelBudget, parameters.GetSecretKeyDist());
        cout << "scaleModSize: " << scaleModSize << endl;
        cout << "bootdepth: " << depth << ", levelBudget: " << levelBudgetElmt << endl;
        cout << "budgetdepth: " << multDepth-depth << endl;
        // cout << "SlotDim: " << logbatchSize << endl;


        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);


        //uint32_t numSlotsBoot=batchSize;
        //uint32_t numSlotsBoot=128;
        TIC(t);
        // cc->EvalBootstrapSetup(levelBudget);
        // cout << "Boot Setup Done" << endl;
        // cc->EvalBootstrapKeyGen(keys.secretKey, batchSize);

        // cc->EvalBootstrapSetup(levelBudget, {0,0}, numSlotsBoot);
        // cout << "Boot Setup Done" << endl;
        // cc->EvalBootstrapKeyGen(keys.secretKey, numSlotsBoot);
        // double timeEval0 =TOC(t);
        // cout<<"Boot Keygen Done: "<< timeEval0 << "ms" << endl;



        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Binary Boot Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        //std::vector<double> x1 = randomDiscreteArray(batchSize, 128);
        //x1[0]=0.1;
        // std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        std::vector<double> x1 = randomIntArray(batchSize, 2);

        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, multDepth - 1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, depth+1);


        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        //cc->LevelReduceInPlace(c1, nullptr, multDepth-1);
        cc->Decrypt(keys.secretKey, c1, &result);
        cout<<"level: " << c1->GetLevel() <<endl;
        TIC(t);
        //c1->SetSlots(numSlotsBoot);
        auto c2 = EvalBinaryBootstrap(c1);
        double timeEval=TOC(t);
        cout<<"level: " << c2->GetLevel() <<endl;

        cc->Decrypt(keys.secretKey, c2, &result);
        precision(result, x1, batchSize);
        result->SetLength(8);
        cout << result << " :: " << "\nEstimated level: " << c2->GetLevel() << ", Time: " << timeEval << std::endl;


        // TIC(t);
        // c2 = cc->EvalBootstrap(c1,2);
        // timeEval=TOC(t);
        // cc->Decrypt(keys.secretKey, c2, &result);
        // precision(result, x1, batchSize);
        // result->SetLength(8);
        // cout << result << " :: " << "\nEstimated level: " << c2->GetLevel() << ", Time: " << timeEval << std::endl;



    } 


    string statTime(const vector<double> times, const usint iteration){
        double avg=0.0;
        double std=0.0;

        if(iteration!=1){
            for(long j=0;j<iteration;j++)avg+=times[j];
            avg/=iteration;
            for(long j=0;j<iteration;j++)std+=(times[j]-avg)*(times[j]-avg);
            std/=iteration;
            std=sqrt(std);
            cout << "Average time = " << avg << ", Std =" << std << endl;
            return "Average time = "+to_string(avg) + ", Std =" +to_string(std);
        }else{
            cout << "Average time = " << times[0] << endl;
            return "Average time = "+to_string(times[0]);
        }
    }

	void logTest(const double bound, const usint degree, const usint iteration, const uint32_t scaleModSize) { 
        TimeVar t;
        vector<double> timeEval(iteration);


        uint32_t multDepth = 25;
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
        cc->Enable(ADVANCEDSHE);

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;
        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Log Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << ", Deg: " << degree <<  std::endl;

        // Inputs
        std::vector<double> x1 = randomRealArray(batchSize, bound);
        for(usint i=0; i<batchSize; i++){
            x1[i]+=1;
        }
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        std::vector<double> x2(batchSize); 
        for(usint i=0; i<batchSize; i++){
            x2[i]=log(x1[i]);
        }
        std::cout << "\n True result: " << std::endl;
        for(usint i=0; i<8; i++){
            cout << x2[i] << " , ";
        }
        cout << endl;
        // Encrypt the encoded vectors
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;


        Ciphertext<DCRTPoly> c2;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            c2 = EvalLog(c1, bound, 0, degree);
            
            
            cc->Decrypt(keys.secretKey, c2, &result);
            precision(result, x2, batchSize);
            result->SetLength(8);
            std::cout << "result = " << result << endl;
            if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        std::cout << "Total: ";
        statTime(timeEval, iteration);


    } 

	void IndicatorTest(const usint bound, const usint iteration, const uint32_t scaleModSize) {
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

        vector<usint> rounds=GenIndicatorRounds(bound, scaleModSize);
        cout << "Rounds: " << rounds << endl;
        usint cleaniter=rounds[1];
        rounds[1]=0;
        Ciphertext<DCRTPoly> c2;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            // if(bound==2){
            //     c2=cc->EvalAdd(c1, 0.001);
            //     c2=IndicatorBinary(c2,rounds);
            // }else{
            c2 = Indicator(c1, bound, rounds, 0);
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

    void IndicatorSIMDTest(const usint bound, const usint iteration, const uint32_t scaleModSize) {
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
        Plaintext numtocheck = GenIndicatorChecker(bound, cc);
        vector<usint> rounds=GenIndicatorRounds(bound, scaleModSize);
        cout << "Rounds: " << rounds << endl;
        usint cleaniter=rounds[1];
        rounds[1]=0;
        Ciphertext<DCRTPoly> c2;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            // if(bound==2){
            //     c2=cc->EvalAdd(c1, 0.001);
            //     c2=IndicatorBinary(c2,rounds);
            // }else{
            c2 = IndicatorSIMD(c1, bound, rounds, numtocheck);
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

    void IndicatorTestDepth30(const usint bound, const usint iteration, const uint32_t scaleModSize) {
        TimeVar t;
        vector<double> timeEval(iteration);
        vector<double> timeSq(iteration);
        vector<double> timeCleanse(iteration);

        uint32_t multDepth = 30;
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
        std::cout << "!!!!!!!!!!!!!!! SqMethod !!!!!!!!!!!!!!!" << std::endl;
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

        vector<usint> rounds=GenIndicatorRounds(bound, scaleModSize);
        cout << "Rounds: " << rounds << endl;
        usint cleaniter=rounds[1];
        rounds[1]=0;
        Ciphertext<DCRTPoly> c2;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            if(bound==2){
                c2=cc->EvalAdd(c1, 0.001);
                c2=IndicatorBinary(c2,rounds);
            }else{
                c2 = Indicator(c1, bound, rounds, 0);
            }
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

	void IndicatorTests(const usint iteration, uint32_t scaleModSize) {
        usint boundbitsrange=7;
        if(scaleModSize>35)boundbitsrange+=2;

        for(usint boundbits=2 ; boundbits < boundbitsrange ; boundbits++){
            usint bound = 1 << boundbits;
            IndicatorTest(bound, iteration, scaleModSize);
        }
    }


	void AnotherIndicatorTests(const usint iteration) {
        usint sf=35;
        IndicatorByLagrangeTest(8,iteration, sf);
        IndicatorByComparisonTest(8, iteration, sf);
        dezTest(3, 8, iteration, sf); 
        IndicatorTestDepth30(8, iteration, sf);

        IndicatorByComparisonTest(64, iteration, sf);
        dezTest(6, 8, iteration, sf); 
        IndicatorTestDepth30(64, iteration, sf);

        sf=50;
        IndicatorByLagrangeTest(8,iteration, sf);
        IndicatorByComparisonTest(8, iteration, sf);
        dezTest(3, 8, iteration, sf); 
        IndicatorTestDepth30(8, iteration, sf);

        IndicatorByComparisonTest(64, iteration, sf);
        dezTest(6, 8, iteration, sf); 
        IndicatorTestDepth30(64, iteration, sf);

        IndicatorByComparisonTest(1024, iteration, sf);
        dezTest(10, 8, iteration, sf); 
        IndicatorTestDepth30(1024, iteration, sf);

    }

    void dezTest(const usint d, const usint K, const usint iteration,  const uint32_t scaleModSize) {
        TimeVar t;
        vector<double> timeEval(iteration);


        uint32_t multDepth = 30;
        uint32_t batchSize = 1 << 16;
        usint bound = 1 << d;
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
        cc->Enable(ADVANCEDSHE);

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;
        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Indicator by Sinc Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << std::endl;

        // Inputs
        std::vector<double> x1 = randomIntArray(batchSize, bound);
        x1[0]=0.0;
        // const double PI = 3.1415926;
        // x1[1]=PI/2;
        // x1[2]=PI;
        // x1[3]=3*PI/4;
        // x1[4]=2*PI;

        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        //std::cout << "\n Input x1: " << ptxt1 << std::endl;

        // Encrypt the encoded vectors
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;


        Ciphertext<DCRTPoly> c2;

        for(usint i=0; i<1; i++){
            TIC(t);
            // vector<double> coscoeff = EvalcoeffCos(K); 
            // c2 = cc->EvalPoly(c1, coscoeff);
            c2 = discreteEqualZero(c1, d, K);
            //cout << coscoeff << endl;
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            cc->Decrypt(keys.secretKey, c2, &result);
            binaryprecision(result, batchSize);
            // result->SetLength(8);
            // std::cout.precision(8);
            //std::cout << "result = " << result << endl;
        }
        cout << "d : " << d << ", K : " << K << endl;
        std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        std::cout << "Total: ";
        statTime(timeEval, iteration);

    } 


    void IndicatorByComparisonTest(const usint bound, const usint iteration, const uint32_t scaleModSize) {
        TimeVar t;
        vector<double> timeEval(iteration);

        uint32_t multDepth = 30;
        uint32_t batchSize = 1 << 16;


        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        //bootSet1(parameters, scaleModSize);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

	    //bootSet2(cc, keys.secretKey, batchSize);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Indicator by Comparison Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        //std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        //std::vector<double> x1 = randomDiscreteArray(batchSize, bound);
        //x1[0]=0.1;
        std::vector<double> x1 = fixedDiscreteArray(batchSize, bound);
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        // ptxt1->SetLength(8);
        // std::cout << "\n Input x1: " << ptxt1 << std::endl;
        
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        for(usint i=0;i<iteration;i++){
            TIC(t);
            auto c2 = comp(c1, (uint32_t)bound, false, false);
            c2 = cc->EvalPoly(c2, {1, 0, -1});
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            cc->Decrypt(keys.secretKey, c2, &result);
            binaryprecision(result, batchSize);
            // result->SetLength(16);
            //cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            
        }
        cout << "\nEstimated level: " << result->GetLevel() << std::endl;

        std::cout << "Total: ";
        statTime(timeEval, iteration);

    } 


    void IndicatorByLagrangeTest(const usint bound, const usint iteration,  const uint32_t scaleModSize) {
        TimeVar t;
        vector<double> timeEval(iteration);


        uint32_t multDepth = 30;
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
        cc->Enable(ADVANCEDSHE);

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;
        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! INDICATOR by Lagrange Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << std::endl;

        // Inputs
        std::vector<double> x1 = randomIntArray(batchSize, bound);
        x1[0]=0.0;
        // const double PI = 3.1415926;
        // x1[1]=PI/2;
        // x1[2]=PI;
        // x1[3]=3*PI/4;
        // x1[4]=2*PI;

        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        // ptxt1->SetLength(8);
        // std::cout << "\n Input x1: " << ptxt1 << std::endl;

        // Encrypt the encoded vectors
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;


        Ciphertext<DCRTPoly> c2;
        vector<double> coeff = GetCoeff(bound);
        for(usint i=0; i<iteration; i++){
            TIC(t);
            // vector<double> coscoeff = EvalcoeffCos(K); 
            // c2 = cc->EvalPoly(c1, coscoeff);
            c2 = IndicatorByLagrange(c1,bound, coeff);
            //cout << coscoeff << endl;
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            cc->Decrypt(keys.secretKey, c2, &result);
            binaryprecision(result, batchSize);
            // result->SetLength(8);
            // std::cout.precision(8);
            //std::cout << "result = " << result << endl;
        }
        std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        std::cout << "Total: ";
        statTime(timeEval, iteration);

    } 


    void ParityTest(const usint d, const usint K, const uint32_t scaleModSize) {
        TimeVar t;
        vector<double> timeEval(1);


        uint32_t multDepth = 25;
        uint32_t batchSize = 1 << 16;
        const usint bound = 1 << d;
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
        cc->Enable(ADVANCEDSHE);

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
        std::cout << "\n Input x1: " << ptxt1 << std::endl;

        // Encrypt the encoded vectors
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;


        Ciphertext<DCRTPoly> c2;

        for(usint i=0; i<1; i++){
            TIC(t);

            c2 = ParityBySin(c1, d, K);
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            cc->Decrypt(keys.secretKey, c2, &result);
            binaryprecision(result, batchSize);
            result->SetLength(8);
            std::cout.precision(8);
            std::cout << "result = " << result << endl;
            std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }




    } 
	// void RoundTest(const usint bound, const usint precis, const usint compprec, const usint iteration, const uint32_t scaleModSize) {
    //     TimeVar t;
    //     vector<double> timeEval(iteration);


    //     uint32_t multDepth = 45;
    //     uint32_t batchSize = 1 << 16;

    //     CCParams<CryptoContextCKKSRNS> parameters;
    //     parameters.SetMultiplicativeDepth(multDepth);
    //     parameters.SetScalingModSize(scaleModSize);
    //     parameters.SetRingDim(batchSize << 1);
    //     parameters.SetBatchSize(batchSize);
        
    //     //cout << "CKKS standard deviation " << parameters.GetStandardDeviation() << endl;
    //     //cout << "CKKS security level " <<  parameters.GetSecurityLevel() << endl;

    //     CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    //     // Enable the features that you wish to use
    //     cc->Enable(PKE);
    //     cc->Enable(KEYSWITCH);
    //     cc->Enable(LEVELEDSHE);
    //     cc->Enable(ADVANCEDSHE);

    //     //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;
    //     paramcheck(cc);

    //     // B. Step 2: Key Generation
    //     auto keys = cc->KeyGen();
    //     cc->EvalMultKeyGen(keys.secretKey);

    //     // Step 3: Encoding and encryption of inputs
    //     std::cout << "!!!!!!!!!!!!!!! Round Test Test !!!!!!!!!!!!!!!" << std::endl;
    //     std::cout << "\nTest on bound: " << bound << ", Precision: " << precis <<  std::endl;

    //     // Inputs
    //     std::vector<double> x1 = randomForRound(batchSize, bound, precis/2);
    //     x1[0]=0.5 - 1/((double)precis);
    //     x1[1]=0.5 + 1/((double)precis);
    //     x1[2]=0.5;


    //     Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    //     ptxt1->SetLength(8);
    //     std::cout << "\n Input x1: " << ptxt1 << std::endl;

    //     // Encrypt the encoded vectors
    //     ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    //     auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    //     Plaintext result;


    //     Ciphertext<DCRTPoly> c2;

    //     for(usint i=0; i<iteration; i++){
    //         TIC(t);
    //         c2 = ParityBySin(c1, log2(bound) ,8);
    //         //cout << coscoeff << endl;
    //         timeEval[i] = TOC(t);
    //         std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
    //         cc->Decrypt(keys.secretKey, c2, &result);
    //         binaryprecision(result, batchSize);

    //         vector<double> vals1 = result->GetRealPackedValue();
    //         usint argmerror=argmaxerror(result, batchSize);
    //         usint argm=argmax(result, batchSize);
    //         cout << "argmaxerror: " << vals1[argmerror] << " from : " << x1[argmerror] << endl;
    //         cout << "argm: " << vals1[argm] << " from : " << x1[argm] << endl;

    //         result->SetLength(8);
    //         std::cout.precision(8);
    //         std::cout << "result = " << result << endl;
    //         std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;


    //         c2 = cc->EvalSub(c2, 0.5);
    //         c2 = comp(c2, (uint32_t)compprec ,false, false);
    //         timeEval[i] = TOC(t);
    //         std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
    //         cc->Decrypt(keys.secretKey, c2, &result);
    //         binaryprecision(result, batchSize);
    //         vector<double> vals2 = result->GetRealPackedValue();

    //         cout << "last argmaxerror: " << vals2[argmerror] << " from : " << vals1[argmerror] << " from : " << x1[argmerror] << endl;
    //         cout << "last argm: " << vals2[argm] <<  " from : " << vals1[argm] << " from : " << x1[argm] << endl;

    //         argmerror=argmaxerror(result, batchSize);
    //         argm=argmax(result, batchSize);
    //         cout << "argmaxerror: " << vals2[argmerror] << " from : " << vals1[argmerror] << " from : " << x1[argmerror] << endl;
    //         cout << "argm: " << vals2[argm] <<  " from : " << vals1[argm] <<" from : " << x1[argm] << endl;

    //         result->SetLength(8);
    //         std::cout.precision(8);
    //         std::cout << "result = " << result << endl;
    //         std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;

    //         c2 = cc->EvalPoly(c2, {1, 0.5, -0.5});
    //         c2 = Cleanse(c2, 4);
    //         timeEval[i] = TOC(t);
    //         std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
    //         cc->Decrypt(keys.secretKey, c2, &result);
    //         binaryprecision(result, batchSize);
    //         result->SetLength(8);
    //         std::cout.precision(8);
    //         std::cout << "result = " << result << endl;
    //         std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;

    //         for(usint j=0;j<8;j++){
    //             cout << ", " << (int)round(x1[j])%2 ;
    //         }
    //         cout << endl;
    //         roundprecision(vals1, x1, batchSize);

    //     }
    //     cout << "bound : " << bound << ", prec : " << precis << endl;
    //     std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
    //     std::cout << "Total: ";
    //     statTime(timeEval, iteration);

    // } 



    void LUTLTTest(const usint bound, const usint outputdimension, const usint iteration) {
        TimeVar t;
        vector<double> timeEval(iteration);
        //vector<double> timeSq(iteration);
        //vector<double> timeCleanse(iteration);

        uint32_t multDepth = 22; // 980
        uint32_t scaleModSize = 35;
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
        //AddRotKeyForEmb(keys.secretKey, cc, bound*outputdimension);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! LUT-LT Test !!!!!!!!!!!!!!!" << std::endl;

        std::cout << "\nTest on bound: " << bound << " , output dimension : " << outputdimension << std::endl;

        // Inputs
        std::vector<double> x = randomIntArray(batchSize, bound);

        std::vector<double> table = randomRealArray(bound*outputdimension, 1.0);

        // for(usint i=0; i<numcode; i++)std::cout << x[i][0] << " , "; /////
        // for(usint i=0; i<16; i++)std::cout << table[i] << " , "; /////

        // Encrypt the encoded vectors
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x);
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        
        Plaintext result;
        vector<double> predict(batchSize);
        usint prec=scaleModSize;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            auto c2 = lookUpTableLT(c1, table, bound, outputdimension);
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            for(usint j=0;j<outputdimension;j++){
                cc->Decrypt(keys.secretKey, c2[j], &result);
                for(usint k=0; k< batchSize;k++){
                    predict[k]=table[bound*j+x[k]];
                }
                usint prectmp = precisionMute(result, predict, batchSize, 1);
                if(prectmp < prec)prec=prectmp;
            }
            cout << "Estimated precision in bits:" << prec << endl;

            // result->SetLength(8);
            // std::cout.precision(8);
            // std::cout << "result = " << result << endl;
            // for(usint i=0; i<8; i++)std::cout << predict[i] << " , ";

            if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        std::cout << "Total: ";
        statTime(timeEval, iteration);


    } 

    void LUTCITest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {
        TimeVar t;
        vector<double> timeEval(iteration);
        //vector<double> timeSq(iteration);
        //vector<double> timeCleanse(iteration);

        uint32_t multDepth = 22; // 980
        uint32_t scaleModSize = 35;
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
        //AddRotKeyForEmb(keys.secretKey, cc, bound*outputdimension);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! LUT-CI Test !!!!!!!!!!!!!!!" << std::endl;

        std::cout << "\nTest on bound: " << bound << ", number of codes: " << numcode <<  " , output dimension : " << outputdimension << std::endl;

        // Inputs
        vector<vector<double>> x(numcode);
        for(usint i=0;i<numcode;i++)x[i] = randomIntArray(batchSize, bound);
        usint totalbound = bound*bound;

        std::vector<double> table = randomRealArray(totalbound*outputdimension, 1.0);

        // for(usint i=0; i<numcode; i++)std::cout << x[i][0] << " , "; /////
        // for(usint i=0; i<16; i++)std::cout << table[i] << " , "; /////

        // Encrypt the encoded vectors
        vector<Ciphertext<DCRTPoly>> c1(numcode);
        for(usint i=0;i<numcode;i++){
            Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x[i]);
            c1[i] = cc->Encrypt(keys.publicKey, ptxt1);
        }        
        Plaintext result;
        vector<double> predict(batchSize);
        usint prec=scaleModSize;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            auto c2 = lookUpTableCI(c1, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            for(usint j=0;j<outputdimension;j++){
                cc->Decrypt(keys.secretKey, c2[j], &result);
                usint base=totalbound*j;
                usint num=0;
                for(usint k=0; k< batchSize;k++){
                    num=(usint)x[0][k]+((usint)x[1][k])*bound;
                    predict[k]=table[base+num];
                }
                usint prectmp = precisionMute(result, predict, batchSize, 1);
                if(prectmp < prec)prec=prectmp;
            }
            cout << "Estimated precision in bits:" << prec << endl;

            // result->SetLength(8);
            // std::cout.precision(8);
            // std::cout << "result = " << result << endl;
            // for(usint i=0; i<8; i++)std::cout << predict[i] << " , ";

            if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        std::cout << "Total: ";
        statTime(timeEval, iteration);


    }



    void CodedLUTTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {
        TimeVar t;
        vector<double> timeEval(iteration);
        //vector<double> timeSq(iteration);
        //vector<double> timeCleanse(iteration);

        uint32_t multDepth = 22; // 980
        uint32_t scaleModSize = 35;
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
        //AddRotKeyForEmb(keys.secretKey, cc, bound*outputdimension);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! CodedHELUT Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << ", number of codes: " << numcode << " , output dimension : " << outputdimension << std::endl;

        // Inputs
        vector<vector<double>> x(numcode);
        for(usint i=0;i<numcode;i++)x[i] = randomIntArray(batchSize, bound);

        std::vector<double> table = randomRealArray(bound*numcode*outputdimension, 1.0);

        // for(usint i=0; i<numcode; i++)std::cout << x[i][0] << " , "; /////
        // for(usint i=0; i<16; i++)std::cout << table[i] << " , "; /////

        // Encrypt the encoded vectors
        vector<Ciphertext<DCRTPoly>> c1(numcode);
        for(usint i=0;i<numcode;i++){
            Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x[i]);
            c1[i] = cc->Encrypt(keys.publicKey, ptxt1);
        }
        Plaintext result;
        vector<double> predict(batchSize);
        usint prec=scaleModSize;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            auto c2 = lookUpTable(c1, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            for(usint j=0;j<outputdimension;j++){
                cc->Decrypt(keys.secretKey, c2[j], &result);
                for(usint k=0; k< batchSize;k++){
                    predict[k]=0;
                    for(usint l=0; l< numcode;l++){
                        usint base = l*bound+bound*numcode*j;
                        predict[k]+=table[base+(usint)x[l][k]];
                    }
                }
                usint prectmp = precisionMute(result, predict, batchSize, 1);
                if(prectmp < prec)prec=prectmp;
            }
            cout << "Estimated precision in bits:" << prec << endl;

            // result->SetLength(8);
            // std::cout.precision(8);
            // std::cout << "result = " << result << endl;
            // for(usint i=0; i<8; i++)std::cout << predict[i] << " , ";

            if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        std::cout << "Total: ";
        statTime(timeEval, iteration);


    } 


	void CodedLUTSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {
        TimeVar t;
        vector<double> timeEval(iteration);
        //vector<double> timeSq(iteration);
        //vector<double> timeCleanse(iteration);

        uint32_t multDepth = 22; // 980
        uint32_t scaleModSize = 35;
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
        AddRotKeyForEmb(keys.secretKey, cc, bound*numcode);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! CodedHELUT SIMD Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << ", number of codes: " << numcode << " , output dimension : " << outputdimension << std::endl;

        // Inputs
        std::vector<double> x1 = randomIntArray(batchSize/bound, bound);
        std::vector<double> table = randomRealArray(bound*numcode*outputdimension, 1.0);

        //for(usint i=0; i<8; i++)std::cout << x1[i] << " , ";
        //for(usint i=0; i<16; i++)std::cout << table[i] << " , ";


        // Encrypt the encoded vectors
        auto c1 = encryptForSIMD(x1, bound, keys.publicKey, cc);
        Plaintext result;
        vector<double> predict(batchSize/(bound*numcode));
        usint prec=scaleModSize;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            auto c2 = lookUpTableSIMD(c1, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            for(usint j=0;j<outputdimension;j++){
                cc->Decrypt(keys.secretKey, c2[j], &result);
                for(usint k=0; k< batchSize/(bound*numcode);k++){
                    predict[k]=0;
                    for(usint l=0; l< numcode;l++){
                        usint base = l*bound + bound*numcode*j;
                        predict[k]+=table[base+(usint)x1[k*numcode+l]];
                    }
                }
                usint prectmp = precisionMute(result, predict, batchSize/(bound*numcode), bound*numcode);
                if(prectmp < prec)prec=prectmp;
            }
            cout << "Estimated precision in bits:" << prec << endl;

            //result->SetLength(8);
            //std::cout.precision(8);
            //std::cout << "result = " << result << endl;
            //for(usint i=0; i<8; i++)std::cout << predict[i] << " , ";

            if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        std::cout << "Total: ";
        statTime(timeEval, iteration);


    } 

 	void LUTSynthTests(const usint bound, const usint numcode, const usint outputdimension, const usint iteration){
        const usint totalbound = 1 << (usint)(log2(bound)*numcode);

        LUTLTTest(totalbound, outputdimension, iteration);
        LUTCITest(bound, numcode, outputdimension, iteration);
        CodedLUTTest(bound, numcode, outputdimension, iteration);
        CodedLUTSIMDTest(bound, numcode, outputdimension, iteration);

    }




    void EmbeddingTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {
        TimeVar t;
        vector<double> timeEval(iteration);
        //vector<double> timeSq(iteration);
        //vector<double> timeCleanse(iteration);

        //uint32_t multDepth = 28; // 980
        uint32_t multDepth = 13;
        if(bound == 16)multDepth+=4;
        uint32_t scaleModSize = 35;
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
        //AddRotKeyForEmb(keys.secretKey, cc, bound*outputdimension);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Embedding Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << ", number of codes: " << numcode << " , output dimension : " << outputdimension << std::endl;

        // Inputs
        vector<vector<double>> x(numcode);
        for(usint i=0;i<numcode;i++)x[i] = randomIntArray(batchSize, bound);

        CompressedEmbedding model(numcode,bound,outputdimension);
        std::vector<double> table = model.weight;

        // for(usint i=0; i<numcode; i++)std::cout << x[i][0] << " , "; /////
        // for(usint i=0; i<16; i++)std::cout << table[i] << " , "; /////

        // Encrypt the encoded vectors
        vector<Ciphertext<DCRTPoly>> c1(numcode);
        for(usint i=0;i<numcode;i++){
            Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x[i]);
            c1[i] = cc->Encrypt(keys.publicKey, ptxt1);
        }
        Plaintext result;
        vector<double> predict(batchSize);
        usint prec=scaleModSize;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            auto c2 = lookUpTable(c1, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            for(usint j=0;j<outputdimension;j++){
                cc->Decrypt(keys.secretKey, c2[j], &result);
                for(usint k=0; k< batchSize;k++){
                    predict[k]=0;
                    for(usint l=0; l< numcode;l++){
                        usint base = l*bound+bound*numcode*j;
                        predict[k]+=table[base+(usint)x[l][k]];
                    }
                }
                usint prectmp = precisionMute(result, predict, batchSize, 1);
                if(prectmp < prec)prec=prectmp;
            }
            cout << "Estimated precision in bits:" << prec << endl;

            // result->SetLength(8);
            // std::cout.precision(8);
            // std::cout << "result = " << result << endl;
            // for(usint i=0; i<8; i++)std::cout << predict[i] << " , ";

            if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        std::cout << "Total: ";
        statTime(timeEval, iteration);


    } 

	void EmbeddingSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {
        TimeVar t;
        vector<double> timeEval(iteration);
        //vector<double> timeSq(iteration);
        //vector<double> timeCleanse(iteration);

        //uint32_t multDepth = 28; // 980
        uint32_t multDepth = 13;
        if(bound == 16)multDepth+=4;
        uint32_t scaleModSize = 35;
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
        AddRotKeyForEmb(keys.secretKey, cc, bound*numcode);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! CodedHELUT SIMD Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << ", number of codes: " << numcode << " , output dimension : " << outputdimension << std::endl;

        // Inputs
        std::vector<double> x1 = randomIntArray(batchSize/bound, bound);
        CompressedEmbedding model(numcode, bound, outputdimension);
        std::vector<double> table = model.weight;

        //for(usint i=0; i<8; i++)std::cout << x1[i] << " , ";
        //for(usint i=0; i<16; i++)std::cout << table[i] << " , ";


        // Encrypt the encoded vectors
        auto c1 = encryptForSIMD(x1, bound, keys.publicKey, cc);
        Plaintext result;
        vector<double> predict(batchSize/(bound*numcode));
        usint prec=scaleModSize;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            auto c2 = lookUpTableSIMD(c1, table, bound, numcode, outputdimension);
            timeEval[i] = TOC(t);
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;
            for(usint j=0;j<outputdimension;j++){
                cc->Decrypt(keys.secretKey, c2[j], &result);
                for(usint k=0; k< batchSize/(bound*numcode);k++){
                    predict[k]=0;
                    for(usint l=0; l< numcode;l++){
                        usint base = l*bound + bound*numcode*j;
                        predict[k]+=table[base+(usint)x1[k*numcode+l]];
                    }
                }
                usint prectmp = precisionMute(result, predict, batchSize/(bound*numcode), bound*numcode);
                if(prectmp < prec)prec=prectmp;
            }
            cout << "Estimated precision in bits:" << prec << endl;

            //result->SetLength(8);
            //std::cout.precision(8);
            //std::cout << "result = " << result << endl;
            //for(usint i=0; i<8; i++)std::cout << predict[i] << " , ";

            if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        std::cout << "Total: ";
        statTime(timeEval, iteration);


    } 

 	void EmbeddingTests(const usint iteration){
        vector<usint> outputdimension={50, 300, 768};
        vector<usint> numcode={8, 16, 32, 64, 32};
        vector<usint> bound={8, 8, 8, 8, 16};

        for(usint i = 0; i<3 ; i++){
            for(usint j = 0; j< 5; j++){
                EmbeddingTest(bound[j], numcode[j], outputdimension[i], iteration);
            }
        }
    }

 	void EmbeddingSIMDTests(const usint iteration){
        vector<usint> outputdimension={50, 300, 768};
        vector<usint> numcode={8, 16, 32, 64, 32};
        vector<usint> bound={8, 8, 8, 8, 16};

        for(usint i = 0; i<3 ; i++){
            for(usint j = 0; j< 5; j++){
                EmbeddingSIMDTest(bound[j], numcode[j], outputdimension[i], iteration);
            }
        }
    }


	void LogregSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {
        TimeVar t;
        vector<double> timeEval1(iteration);
        vector<double> timeEval2(iteration);
        vector<double> timeEval(iteration);

        //vector<double> timeSq(iteration);
        //vector<double> timeCleanse(iteration);

        //uint32_t multDepth = 28; // 980
        uint32_t multDepth = 40;
        // if(bound == 16)multDepth+=4;
        uint32_t scaleModSize = 35;
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
        cc->Enable(ADVANCEDSHE);

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForEmb(keys.secretKey, cc, batchSize);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! LogisticRegression SIMD Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << ", number of codes: " << numcode << " , output dimension : " << outputdimension << std::endl;

        // Inputs
        std::vector<string> sentence = 	readsentence(512, 2, 128); ////// INvalid!!!!!!
        CompressedEmbedding model(numcode, bound, outputdimension);
        LogregModel logreg(numcode, bound, outputdimension);
        std::vector<double> table = model.weight;

        //for(usint i=0; i<8; i++)std::cout << x1[i] << " , ";
        //for(usint i=0; i<16; i++)std::cout << table[i] << " , ";


        // Encrypt the encoded vectors
        const usint numpredicts = batchSize/(bound*numcode*512);
        vector<usint> lengthvec(numpredicts);
        for(usint i=0; i< numpredicts; i++){
            usint count = 512;
            for(usint j=0; j<512;j++){
                if(sentence[512*i+j]=="<pad>")count-=1;
            }
            lengthvec[i]=count;
        }
        // std::cout << lengthvec << std::endl;
        auto c1 = encrypt_sentence_SIMD(cc, keys.publicKey, sentence, model);
        Plaintext result;
        vector<usint> answer = readlabels(0, 128);/// Invalid!!!!!!!!!!!!
        vector<usint> predict(numpredicts);
        usint auc=0;

        for(usint i=0; i<iteration; i++){
            TIC(t);
            auto c2 = lookUpTableSIMD(c1, table, bound, numcode, outputdimension);
            timeEval1[i] = TOC(t);
            cout << "level: " << c2[0]->GetLevel() << ", Time: " << timeEval1[i] << endl;
            TIC(t);
            auto c3 = inference_encrypted_SIMD(c2, 512, lengthvec, model, logreg);
            timeEval2[i] = TOC(t);
            cout << "level: " << c3->GetLevel() << ", Time: " << timeEval2[i] << endl;
            timeEval[i] = timeEval1[i] + timeEval2[i];
            std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;

            cc->Decrypt(keys.secretKey, c3, &result);
            vector<double> res = result->GetRealPackedValue();

            for(usint k=0; k< numpredicts; k++){
                if(res[bound*numcode*512*k] > 0.5){
                    predict[k]=1;
                }else{
                    predict[k]=0;
                }
                cout << res[bound*numcode*512*k] << endl;

                if(predict[k]==answer[k]){
                    auc+=1;
                }
            }
            cout << "Estimated accuracy:" << auc << " per " << numpredicts << endl;

            //result->SetLength(8);
            //std::cout.precision(8);
            //std::cout << "result = " << result << endl;
            //for(usint i=0; i<8; i++)std::cout << predict[i] << " , ";

            // if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        std::cout << "LUT: ";
        statTime(timeEval1, iteration);
        std::cout << "Inference: ";
        statTime(timeEval2, iteration);
        std::cout << "Total: ";
        statTime(timeEval, iteration);


    } 

    void LogregSIMDTests(const usint iteration){
        vector<usint> outputdimension={50, 300};
        vector<usint> numcode={8, 16, 32, 64, 32};
        vector<usint> bound={8, 8, 8, 8, 16};

        for(usint i = 0; i<2 ; i++){
            for(usint j = 0; j< 5; j++){
                LogregSIMDTest(bound[j], numcode[j], outputdimension[i], iteration);
            }
        }
    }


	void LogregTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration) {
        TimeVar t;
        // vector<double> timeEval1(iteration);
        vector<double> timeEval2(iteration);
        // vector<double> timeEval(iteration);

        vector<string> resultlog(iteration+2);
        resultlog[0] = "Test on bound: " + to_string(bound) + ", number of codes: " + to_string(numcode) + " , output dimension : " + to_string(outputdimension);

        //vector<double> timeSq(iteration);
        //vector<double> timeCleanse(iteration);

        //uint32_t multDepth = 28; // 980
        uint32_t multDepth = 13;
        if(bound == 16)multDepth+=4;
        uint32_t scaleModSize = 35;
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
        cc->Enable(ADVANCEDSHE);

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForEmb(keys.secretKey, cc, 512);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! LogisticRegression Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "\nTest on bound: " << bound << ", number of codes: " << numcode << " , output dimension : " << outputdimension << std::endl;

        // Inputs

        CompressedEmbedding model(numcode, bound, outputdimension);
        LogregModel logreg(numcode, bound, outputdimension);
        //for(usint i=0; i<8; i++)std::cout << x1[i] << " , ";
        //for(usint i=0; i<16; i++)std::cout << table[i] << " , ";

        // Encrypt the encoded vectors

        const usint numpredicts = batchSize/(512);
        vector<usint> lengthvec(numpredicts);
        
        // std::cout << lengthvec << std::endl;
        
        usint totalauc=0;
        // double totalloss = 0.0;
        double maxerror = 0.0;


        for(usint i=0; i<iteration; i++){
            std::vector<string> sentence = 	readsentence(512, i, 128);
            for(usint i=0; i< numpredicts; i++){
                usint count = 512;
                for(usint j=0; j<512;j++){
                    if(sentence[512*i+j]=="<pad>")count-=1;
                    // if(sentence[512*i+j]=="<unk>")count-=1;
                }
                lengthvec[i]=count;
            }
            // auto c1 = encrypt_sentence(cc, keys.publicKey, sentence, model);
            Plaintext result;
            vector<usint> answer = readlabels(i, 128);
            vector<usint> predict(numpredicts);
            usint auc=0;

            vector<vector<double>> emb = sentencembedding_plain(cc, sentence, model);
            vector<Ciphertext<DCRTPoly>> c2(model.outputdimension);
            for(usint j=0;j<model.outputdimension; j++){
                Plaintext ptxt = cc->MakeCKKSPackedPlaintext(emb[j]);
                c2[j] = cc->Encrypt(keys.publicKey, ptxt);
            }
            // TIC(t);
            // auto c2 = lookUpTable(c1, table, bound, numcode, outputdimension);
            // timeEval1[i] = TOC(t);
            // cout << "level: " << c2[0]->GetLevel() << ", Time: " << timeEval1[i] << endl;
            TIC(t);
            auto c3 = inference_encrypted(c2, 512, lengthvec, model, logreg);
            timeEval2[i] = TOC(t);
            cout << "level: " << c3->GetLevel() << ", Time: " << timeEval2[i] << endl;
            // timeEval[i] = timeEval1[i] + timeEval2[i];
            // std::cout << "Evaluation time: " << timeEval[i] << " ms" << std::endl;

            vector<double> predict_val = inference_plain(cc, emb, 512, lengthvec, model, logreg);
            // double loss = 0;
            cc->Decrypt(keys.secretKey, c3, &result);
            vector<double> res = result->GetRealPackedValue();
            // double maxx = 0;
            // for(usint k=0; k<batchSize;k++){
            //     if(maxx < res[k])maxx = res[k];
            //     if(maxx < -res[k])maxx = -res[k];

            // }
            // cout << "maximum " << maxx << endl;

            for(usint k=0; k< numpredicts; k++){
                if(res[512*k] > 0){
                    predict[k]=1;
                }else{
                    predict[k]=0;
                }
                // cout << res[512*k] << ", " << predict_val[k] << endl;
                double tmpgap= predict_val[k]-res[512*k];
                if(maxerror < tmpgap)maxerror = tmpgap;
                if(maxerror < -tmpgap)maxerror = -tmpgap;

                if(predict[k]==answer[k]){
                    auc+=1;
                }

                // loss += (predict_val[k]-res[512*k]) * (predict_val[k]-res[512*k]);

            }
            // loss /= (double) numpredicts;
            totalauc+=auc;
            // totalloss+=loss;
            cout << "Estimated accuracy:" << auc << " per " << numpredicts << ", Maxerror: " << maxerror << endl;
            resultlog[i+1] =to_string(timeEval2[i])+ "Estimated accuracy:" + to_string(auc) + " per " + to_string(numpredicts) + ", Maxerror: " + to_string(maxerror);

            //result->SetLength(8);
            //std::cout.precision(8);
            //std::cout << "result = " << result << endl;
            //for(usint i=0; i<8; i++)std::cout << predict[i] << " , ";

            // if(i==iteration-1)std::cout << "\nEstimated level: " << result->GetLevel() << std::endl;
        }

        // std::cout << "LUT: ";
        // statTime(timeEval1, iteration);
        std::cout << "Inference: ";
        string st = statTime(timeEval2, iteration);
        // std::cout << "Total: ";
        // statTime(timeEval, iteration);
        // cout << "Estimated accuracy:" << (double)totalauc /(double)(numpredicts*iteration) << ", Loss: " << totalloss / (double)iteration << ", " << -log2(totalloss / (double)iteration) <<  endl;
        cout << "Estimated accuracy:" << (double)totalauc /(double)(numpredicts*iteration) << ", maxerror: " << maxerror << ", " << -log2(maxerror) <<  endl;
        resultlog[iteration+1] = st + "Estimated accuracy:" + to_string((double)totalauc /(double)(numpredicts*iteration)) + ", maxerror: " + to_string(maxerror) + ", " + to_string(-log2(maxerror));

	    addRes(resultlog, "logreg_result.txt", iteration);

    } 

    void LogregTests(const usint iteration){
        vector<usint> outputdimension={50, 300};
        vector<usint> numcode={8, 16, 32, 64, 32};
        vector<usint> bound={8, 8, 8, 8, 16};

        for(usint i = 0; i<2 ; i++){
            for(usint j = 0; j< 5; j++){
                if(checkline("logreg_result.txt") < (iteration+2)*(5*i+j+1))LogregTest(bound[j], numcode[j], outputdimension[i], iteration);
            }
        }
    }

    void ComparisonTests(const uint32_t scaleModSize, const uint32_t bound) {

        uint32_t multDepth = 52; // maximum 52 for delta 40, 59 for delta 35
        uint32_t batchSize = 1 << 16;

        //usint limit= ((multDepth-16)/(4))+1-2;
        

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
        cc->Enable(ADVANCEDSHE);

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Comparison Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        std::vector<double> x1 = fixedDiscreteArray(batchSize, bound);
        //x1[0]=0.1;
        //x1[1]=1.0;
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        //std::cout << "\n Input x1: " << ptxt1 << std::endl;

        for(usint i=0;i<8;i++)cout << x1[i] << ", ";
        cout << endl;
        // Encrypt the encoded vectors
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;
        std::cout.precision(4);

        for(usint j=2; j<6; j++){
            auto c2 = comparison(c1, 0, j, 1.0, 3);
            cc->Decrypt(keys.secretKey, c2, &result);
            cout << "-----------------degg: " << j << " :: " ;
            compprecision(c2, x1, batchSize, cc, keys);
            binaryprecision(result, batchSize);
            result->SetLength(8);
            cout << result << " :: " <<endl;
            for(usint i=1; i<4; i++){
                c2 = comparison(c2, 1, 0, 1.0,3);
                cc->Decrypt(keys.secretKey, c2, &result);
                cout << "degf: " << i << ", degg: " << j << " :: ";
                compprecision(c2, x1, batchSize, cc, keys);
                binaryprecision(result, batchSize);
                result->SetLength(8);
                cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            }
            
        }



    } 


    void ComparisonTest(const uint32_t scaleModSize, const uint32_t bound) {

        uint32_t multDepth = 52;
        uint32_t batchSize = 1 << 16;


        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        //bootSet1(parameters, scaleModSize);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

	    //bootSet2(cc, keys.secretKey, batchSize);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Comparison Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        //std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        //std::vector<double> x1 = randomDiscreteArray(batchSize, bound);
        //x1[0]=0.1;
        std::vector<double> x1 = fixedDiscreteArray(batchSize, bound);
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        for(usint i=0;i<1;i++){
            auto c2 = comp(c1, (uint32_t)bound, false, false);
            cc->Decrypt(keys.secretKey, c2, &result);
            binaryprecision(result, batchSize);
            result->SetLength(16);
            cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            
        }


    } 

    void BDtest(const uint32_t scaleModSize, const uint32_t bound, const usint iter) {
        TimeVar t;
        // vector<double> timeEval(1);
        double timeEval=0;

        uint32_t multDepth = 2320/scaleModSize;
        uint32_t batchSize = 1 << 16;


        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        

        //bootSet1(parameters, scaleModSize);

        parameters.SetFirstModSize(scaleModSize+1);
        parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);
	    parameters.SetSecretKeyDist(SPARSE_TERNARY);
        parameters.SetNumLargeDigits(0);
        parameters.SetKeySwitchTechnique(HYBRID);

        //parameters.SetSecurityLevel(HEStd_NotSet);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);
        cout << "multDepth :" << multDepth << endl;


        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        //AddRotKeyForEmb(keys.secretKey, cc, batchSize);
        TIC(t);
	    bootSet2(cc, keys.secretKey, batchSize);
        cout << "bootset: " << TOC(t) << endl;
        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Bit Decomposition Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        //std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        //std::vector<double> x1 = randomDiscreteArray(batchSize, bound);
        //x1[0]=0.1;
        std::vector<double> x1 = randomIntArray(batchSize, bound);
        // x1[0]=128.0;
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;
        cout << iter << endl;

        for(usint i=0;i<1;i++){
            TIC(t);
            //auto c2 = ExtractMSB(c1, bound);
	        // auto c2 = ExtractLSB(c1, bound);
            //vector<Ciphertext<DCRTPoly>> c2 =  ExtractMSBs(c1, bound, iter);
            vector<Ciphertext<DCRTPoly>> c2 =  ExtractLSBs(c1, bound, log2(bound));
            // vector<Ciphertext<DCRTPoly>> c2 = DecompToBits(c1, log2(bound), (usint)multDepth);


            // cc->Decrypt(keys.secretKey, c2, &result);
            // binaryprecision(result, batchSize);
            // result->SetLength(16);
            // cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            timeEval=TOC(t);
            for(usint j=0;j<c2.size();j++){
                cc->Decrypt(keys.secretKey, c2[j], &result);
                binaryprecision(result, batchSize);
                result->SetLength(16);
                cout << j << "th bit :: " << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            }
            cout << "Eval Time: " << timeEval << std::endl;

        }


    } 

 
    void NaiveCountTest(const uint32_t scaleModSize, const uint32_t bound, usint size, const usint iteration) {

        TimeVar t;
        vector<double> timeEval(iteration);
        uint32_t multDepth = 2320/scaleModSize - 4;
        uint32_t batchSize = 1 << 16;
        if(size==0)size=batchSize;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        //bootSet1(parameters, scaleModSize);
        //parameters.SetSecurityLevel(HEStd_NotSet);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForEmb(keys.secretKey, cc, size);

	    //bootSet2(cc, keys.secretKey, batchSize);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Naive Count Decomposition Test !!!!!!!!!!!!!!!" << std::endl;
        std::cout << "bound:  " << bound << ", size: " << size << std::endl;

        // Inputs
        //std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        //std::vector<double> x1 = randomDiscreteArray(batchSize, bound);
        //x1[0]=0.1;
        std::vector<double> x1 = randomIntArray(size, bound);
        vector<double> x00= fullCopy(x1, batchSize, size);

        // x1[0]=128.0;
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x00);

        
        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

        Plaintext result;
        double prec = 100;
        for(usint i=0;i<iteration;i++){
            TIC(t);
            vector<Ciphertext<DCRTPoly>> c2 = NaiveCount(c1, bound, size);
            timeEval[i] = TOC(t);

            // cc->Decrypt(keys.secretKey, c2, &result);
            // binaryprecision(result, batchSize);
            // result->SetLength(16);
            // cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            
            for(usint j=0;j<c2.size();j++){
                cc->Decrypt(keys.secretKey, c2[j], &result);

                double prectmp = countprecisionMute(result, x1, size, j);
                if(prectmp < prec)prec=prectmp;
                if(prec < 3 || prec > 90){
                    result->SetLength(16);
                    cout << "Prec: " << prec << endl;
                    cout << j << "th counting :: " << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
                    break;
                }
            }
            result->SetLength(16);
            cout << "Prec: " << prec << ", Time: " << timeEval[i] << endl;
            cout << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
        }
        statTime(timeEval, iteration);

    } 


    void CodedCountTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint exponentbound, const usint iteration) {
        TimeVar t;
        vector<double> timeEval0(iteration);
        vector<double> timeEval1(iteration);
        vector<double> timeEval2(iteration);
        vector<double> timeEvalTotal(iteration);


        uint32_t multDepth = 2320/scaleModSize - 4;
        uint32_t batchSize = 1 << 16;
        if(size==0)size=batchSize;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        //bootSet1(parameters, scaleModSize);
        //parameters.SetSecurityLevel(HEStd_NotSet);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForEmb(keys.secretKey, cc, size);

	    //bootSet2(cc, keys.secretKey, batchSize);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Coded Count Decomposition Test !!!!!!!!!!!!!!!" << std::endl;
        cout << "Size: " << size << ", Base: " << base << ", Dim: " << dim << ", Total bound: " << pow(base,dim) << endl;
        // Inputs
        //std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        //std::vector<double> x1 = randomDiscreteArray(batchSize, bound);
        //x1[0]=0.1;
        std::vector<double> x1(size);
        vector<Ciphertext<DCRTPoly>> c1(dim);
        usint currentbase=1;
        for(usint i=0; i<dim; i++){
            std::vector<double> x0 = randomIntArray(size, base);
            for(usint j=0;j<size;j++){
                x1[j]+=x0[j]*currentbase;
            }
            vector<double> x00= fullCopy(x0, batchSize, size);
            currentbase*=base;
            Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x00);
            c1[i] = cc->Encrypt(keys.publicKey, ptxt1);
        }
        // cout << x1 << endl;

        // Encrypt the encoded vectors
        Plaintext result;
        double prec = 100;
        for(usint i=0;i<iteration;i++){
            TIC(t);
            vector<Ciphertext<DCRTPoly>> ohe = ToOHE(c1, base);
            timeEval0[i]=TOC(t);
            TIC(t);
            cout << "ToOHE: " << ohe.size() << ", Time: " << timeEval0[i] << endl; 
            vector<Ciphertext<DCRTPoly>> basis = MakeBasis(ohe, base, exponentbound);
            timeEval1[i]=TOC(t);
            TIC(t);
            cout << "basis: " << basis.size() << ", Time: " << timeEval1[i] << endl;
            vector<Ciphertext<DCRTPoly>> c2 = Count(basis, base, size, dim, exponentbound, 0);
            timeEval2[i]=TOC(t);
            timeEvalTotal[i]= timeEval0[i]+timeEval1[i]+timeEval2[i];
            cout << "Time: " << timeEval2[i] << ", Total: " << timeEvalTotal[i] << endl;

            // for(usint j=0;j<basis.size();j++){
            //     cc->Decrypt(keys.secretKey, basis[j], &result);
            //     result->SetLength(8);
            //     cout << j <<" , " << result << endl;
            // }

            for(usint j=0;j<c2.size();j++){
                cc->Decrypt(keys.secretKey, c2[j], &result);
                

                double prectmp = CodedcountprecisionMute(result, x1, size, j, false);
                if(prectmp < prec)prec=prectmp;
                if(prec < 3 || prec > 90){
                    result->SetLength(16);
                    cout << "Prec: " << prec << endl;
                    cout << j << "th counting :: " << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
                    break;
                }
            }
            // result->SetLength(16);
            cout << "Prec: " << prec << endl;
            cout << " :: " << "\nEstimated level: " << c2[0]->GetLevel() << std::endl;
        }
        statTime(timeEval0, iteration);
        statTime(timeEval1, iteration);
        statTime(timeEval2, iteration);
        statTime(timeEvalTotal, iteration);

    } 

    void CodedCountSIMDTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint maxlen, const usint iteration) {
        TimeVar t;
        vector<double> timeEval0(iteration);
        vector<double> timeEval1(iteration);
        vector<double> timeEval2(iteration);
        vector<double> timeEvalTotal(iteration);


        uint32_t multDepth = 2320/scaleModSize - 4;
        uint32_t batchSize = 1 << 16;
        if(size==0)size=batchSize;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        //bootSet1(parameters, scaleModSize);
        //parameters.SetSecurityLevel(HEStd_NotSet);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        std::cout << "!!!!!!!!!!!!!!! Coded Count SIMD Test !!!!!!!!!!!!!!!" << std::endl;
        cout << "Size: " << size << ", Base: " << base << ", Dim: " << dim << ", Total bound: " << pow(base,dim) << endl;

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForEmb(keys.secretKey, cc, size);
        AddRotKeyForCountSIMD(keys.secretKey, cc, base, size, batchSize, pow(base,dim));



	    //bootSet2(cc, keys.secretKey, batchSize);

        // Step 3: Encoding and encryption of inputs
        // Inputs
 
        // std::vector<double> x1(size);
        // vector<Ciphertext<DCRTPoly>> c1(dim);
        // usint currentbase=1;
        // // std::vector<double> x0 = randomIntArray(size, base);
        // std::vector<usint> x0 = fixedIntArray(maxlen, pow(base,dim));
        // // for(usint k=0; k<8; k++)cout << x0[k] << ", " << endl;
        // for(usint i=0; i<dim; i++){
        //     for(usint j=0;j<maxlen;j++){
        //         usint tmps = x0[j];
        //         tmps=tmps/currentbase;
        //         tmps= tmps%base;
        //         x1[j]=(double)tmps;
        //     }
        //     // for(usint k=0; k<8; k++)cout << x0[k] << ", " << endl;

        //     vector<double> x00= fullCopy(x1, batchSize, size);
        //     currentbase*=base;
        //     Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x00);
        //     c1[i] = cc->Encrypt(keys.publicKey, ptxt1);
        // }


        std::vector<double> x1(size);
        vector<Ciphertext<DCRTPoly>> c1(dim);
        usint currentbase=1;
        for(usint i=0; i<dim; i++){
            std::vector<double> x0 = randomIntArray(maxlen, base);
            for(usint j=0;j<maxlen;j++){
                x1[j]+=x0[j]*currentbase;
            }
            vector<double> x00= fullCopy(x0, batchSize, size);
            currentbase*=base;
            Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x00);
            c1[i] = cc->Encrypt(keys.publicKey, ptxt1);
        }

        // cout << x1 << endl;
        cout << "Start" << endl;
        // Encrypt the encoded vectors
        Plaintext result;
        // double prec = 100;
        for(usint i=0;i<iteration;i++){
            TIC(t);
            vector<Ciphertext<DCRTPoly>> ohe = ToOHESIMD(c1, base, size);
            timeEval0[i]=TOC(t);
            TIC(t);
            cout << "ToOHE: " << ohe.size() << ", Time: " << timeEval0[i] << endl; 
            vector<Ciphertext<DCRTPoly>> basis = MakeBasisSIMD(ohe, base, size, 0);
            timeEval1[i]=TOC(t);
            TIC(t);
            cout << "basis: " << basis.size() << ", Time: " << timeEval1[i] << endl;
            vector<Ciphertext<DCRTPoly>> c2 = CountSIMD(basis, base, size, maxlen, dim);
            timeEval2[i]=TOC(t);
            timeEvalTotal[i]= timeEval0[i]+timeEval1[i]+timeEval2[i];
            cout << "Time: " << timeEval2[i] << ", Total: " << timeEvalTotal[i] << endl;

  
            // cc->Decrypt(keys.secretKey, basis[0], &result);
            // vector<double> vals0 = result->GetRealPackedValue();

            // for(usint j=0;j<4;j++){
            //     for(usint k=0;k<4;k++){
            //         cout << vals0[j*size+k] <<", " ;
            //     }
            //     cout << endl;
            // }
            // cout << "----" << endl;
            // cc->Decrypt(keys.secretKey, c2[0], &result);
            // vector<double> vals1 = result->GetRealPackedValue();

            // for(usint j=0;j<4;j++){

            //     cout << vals1[j*size] <<", " ;
            // }
            // cout << endl;


            // for(usint j=0;j<c2.size();j++){
            //     cc->Decrypt(keys.secretKey, c2[j], &result);
                

            //     double prectmp = CodedcountprecisionMute(result, x1, size, j, false);
            //     if(prectmp < prec)prec=prectmp;
            //     if(prec < 3 || prec > 90){
            //         result->SetLength(16);
            //         cout << "Prec: " << prec << endl;
            //         cout << j << "th counting :: " << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            //         break;
            //     }
            // }

            // result->SetLength(16);
            // cout << "Prec: " << prec << endl;
            cout << " :: " << "\nEstimated level: " << c2[0]->GetLevel() <<  std::endl;
        }
        statTime(timeEval0, iteration);
        statTime(timeEval1, iteration);
        statTime(timeEval2, iteration);
        statTime(timeEvalTotal, iteration);

    } 

	void NgramTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint exponentbound, const usint n, const double ratio, const usint iteration){
        TimeVar t;
        vector<double> timeEval0(iteration);
        vector<double> timeEval1(iteration);
        vector<double> timeEval2(iteration);
        vector<double> timeEvalTotal(iteration);


        uint32_t multDepth = 2320/scaleModSize - 4;
        uint32_t batchSize = 1 << 16;
        if(size==0)size=batchSize;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        //bootSet1(parameters, scaleModSize);
        //parameters.SetSecurityLevel(HEStd_NotSet);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForEmb(keys.secretKey, cc, size);
        std::vector<int32_t> arr(n-1);
        for(int32_t i=1;i<3;i++)arr[i-1]=-i;
        cc->EvalRotateKeyGen(keys.secretKey, arr);

	    //bootSet2(cc, keys.secretKey, batchSize);

        // Step 3: Encoding and encryption of inputs
        usint bound = pow(pow(base, dim), n);
        // usint partialbound = (bound * ratio) / 100;
        double partialbounddouble = ((double)bound * ratio) / 100.0;
        usint partialbound = (usint)partialbounddouble;
        if(partialbound > bound || partialbound == 0)partialbound=bound;
        std::cout << "!!!!!!!!!!!!!!! Ngram Test !!!!!!!!!!!!!!!" << std::endl;
        cout << n << "-gram, Size: " << size << ", Base: " << base << ", Dim: " << dim << ", Total bound: " << pow(base,dim) << ", Partial bound: " << partialbound << endl;
        // Inputs
        //std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        //std::vector<double> x1 = randomDiscreteArray(batchSize, bound);
        //x1[0]=0.1;
        std::vector<double> x1(size);
        vector<Ciphertext<DCRTPoly>> c1(dim);
        usint currentbase=1;
        for(usint i=0; i<dim; i++){
            std::vector<double> x0 = randomIntArray(size, base);
            for(usint j=0;j<size;j++){
                x1[j]+=x0[j]*currentbase;
            }
            vector<double> x00= fullCopy(x0, batchSize, size);
            currentbase*=base;
            Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x00);
            c1[i] = cc->Encrypt(keys.publicKey, ptxt1);
        }
        // cout << x1 << endl;


        // Encrypt the encoded vectors
        // Plaintext result;
        // double prec = 100;
        for(usint i=0;i<iteration;i++){
            TIC(t);
            vector<Ciphertext<DCRTPoly>> ohe = ToOHE(c1, base);
            vector<Ciphertext<DCRTPoly>> basis = MakeBasis(ohe, base, exponentbound, true);
            timeEval0[i]=TOC(t);
            cout << "BasisConstruction: " << basis.size() << ", Time: " << timeEval0[i] << endl; 
            vector<Ciphertext<DCRTPoly>>().swap(ohe); //Delete vector
            TIC(t);
            vector<Ciphertext<DCRTPoly>> ngrambasis = NgramBasis(basis, n);
            timeEval1[i]=TOC(t);
            vector<Ciphertext<DCRTPoly>>().swap(basis); //Delete vector
            cout << "Ngrambasis: " << ngrambasis.size() << ", Time: " << timeEval1[i] << endl;
            TIC(t);
            vector<Ciphertext<DCRTPoly>> c2 = Ngram(ngrambasis, base, size, dim, exponentbound, n, ratio, true);
            timeEval2[i]=TOC(t);
            timeEvalTotal[i]= timeEval0[i]+timeEval1[i]+timeEval2[i];
            cout << "Time: " << timeEval2[i] << ", Total: " << timeEvalTotal[i] << endl;
            cout << "Estimated level: " << c2[0]->GetLevel() << endl;
            // for(usint j=0;j<basis.size();j++){
            //     cc->Decrypt(keys.secretKey, basis[j], &result);
            //     result->SetLength(8);
            //     cout << j <<" , " << result << endl;
            // }

            // for(usint j=0;j<c2.size();j++){
            //     cc->Decrypt(keys.secretKey, c2[j], &result);
                

            //     double prectmp = CodedcountprecisionMute(result, x1, size, j, false);
            //     if(prectmp < prec)prec=prectmp;
            //     if(prec < 3 || prec > 90){
            //         result->SetLength(16);
            //         cout << "Prec: " << prec << endl;
            //         cout << j << "th counting :: " << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            //         break;
            //     }
            // }
            // result->SetLength(16);
            // cout << "Prec: " << prec << endl;
            // cout << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
        }
        statTime(timeEval0, iteration);
        statTime(timeEval1, iteration);
        statTime(timeEval2, iteration);
        statTime(timeEvalTotal, iteration);

    } 

    void InfoRetrievalTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint vocabsize, const usint exponentbound, const usint iteration) {
        TimeVar t;
        vector<double> timeEval0(iteration);
        vector<double> timeEval1(iteration);
        vector<double> timeEval2(iteration);
        vector<double> timeEvalTotal(iteration);


        // uint32_t multDepth = 2320/scaleModSize - 4;
        uint32_t multDepth = 43;

        uint32_t batchSize = 1 << 16;
        if(size==0)size=batchSize;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        //bootSet1(parameters, scaleModSize);
        //parameters.SetSecurityLevel(HEStd_NotSet);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForIR(keys.secretKey, cc, size, batchSize);

	    //bootSet2(cc, keys.secretKey, batchSize);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Info Retrieval Test !!!!!!!!!!!!!!!" << std::endl;
        cout << "Size: " << size << ", Base: " << base << ", Dim: " << dim << ", Total bound: " << pow(base,dim) << endl;
        // Inputs
        //std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        //std::vector<double> x1 = randomDiscreteArray(batchSize, bound);
        //x1[0]=0.1;
        Plaintext text = loadtext(cc, size, 1024);
    	vector<Plaintext> tfidf = loadtfidf(cc, size, vocabsize, batchSize);
	    vector<Plaintext> idf = loadidf(cc, size, vocabsize, batchSize, false, pow(base,dim)-1);
	    vector<Plaintext> querytext = loadquery(cc, base, dim, size, batchSize, 8); 

        vector<Ciphertext<DCRTPoly>> c1(dim);
        for(usint i=0; i<dim;i++)c1[i] = cc->Encrypt(keys.publicKey, querytext[i]);

        // Encrypt the encoded vectors
        Plaintext result;
    

        for(usint i=0;i<iteration;i++){
            TIC(t);
            vector<Ciphertext<DCRTPoly>> ohe = ToOHE(c1, base);
            vector<Ciphertext<DCRTPoly>> basis = MakeBasis(ohe, base, exponentbound);
            vector<Ciphertext<DCRTPoly>> counted = Count(basis, base, 256, dim, exponentbound, size);
            vector<Ciphertext<DCRTPoly>> doc = IDFMult(counted, size, idf);
            timeEval0[i]=TOC(t);
            cout << "TFIDF: " << doc.size() << ", Time: " << timeEval0[i] << ", Estimated level: " << doc[0]->GetLevel() << endl;

            // cc->Decrypt(keys.secretKey, counted[1], &result);    
            // result->SetLength(16);
            // cout << result << endl;

            vector<Ciphertext<DCRTPoly>>().swap(ohe); //Delete vector
            vector<Ciphertext<DCRTPoly>>().swap(basis); //Delete vector
            vector<Ciphertext<DCRTPoly>>().swap(counted); //Delete vector

            TIC(t);
            vector<Ciphertext<DCRTPoly>> dist = DistanceComparison(doc, size, tfidf);
            timeEval1[i]=TOC(t);
            cout << "DistanceComparison: " << dist.size() << ", Time: " << timeEval1[i] << ", Estimated level: " << dist[2]->GetLevel() << endl;

            TIC(t);
            Ciphertext<DCRTPoly> c2 = Retrieval(dist[2], size, text);
            timeEval2[i]=TOC(t);
            timeEvalTotal[i]= timeEval0[i]+timeEval1[i]+timeEval2[i];
            cout << "Retrieval Time: " << timeEval2[i] << ", Total: " << timeEvalTotal[i] << ", Estimated level: " << c2->GetLevel() << endl;

            // cc->Decrypt(keys.secretKey, c2[0], &result);   
            // writetext(result, size, "eucdistresult.txt", 1);
            // result->SetLength(16);
            // cout << result << endl;

            // cc->Decrypt(keys.secretKey, c2[1], &result); 
            // writetext(result, size, "compresult.txt", 1);
            // result->SetLength(16);
            // cout << result << endl;


            cc->Decrypt(keys.secretKey, c2, &result);    
            // writetext(result, size, "retrieved.txt", 1024);
            writetext(result, size, to_string(size)+to_string(i)+"retrievednumber.txt", 1024);
            mapandwritetext(result, size, to_string(size)+to_string(i)+"retrievedtext.txt", 1024);

            result->SetLength(16);
            cout << result << endl;
            cout << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
        }
        statTime(timeEval0, iteration);
        statTime(timeEval1, iteration);
        statTime(timeEval2, iteration);
        statTime(timeEvalTotal, iteration);

    } 



    void InfoRetrievalAfterTFTest(const uint32_t scaleModSize, usint size, const usint vocabsize, const usint iteration) {
        TimeVar t;
        vector<double> timeEval0(iteration);
        vector<double> timeEval1(iteration);
        vector<double> timeEval2(iteration);
        vector<double> timeEvalTotal(iteration);


        uint32_t multDepth = 2320/scaleModSize - 4;
        // uint32_t multDepth = 43;

        uint32_t batchSize = 1 << 16;
        if(size==0)size=batchSize;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        //bootSet1(parameters, scaleModSize);
        //parameters.SetSecurityLevel(HEStd_NotSet);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForPo2(keys.secretKey, cc, batchSize);

	    //bootSet2(cc, keys.secretKey, batchSize);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Info Retrieval Test !!!!!!!!!!!!!!!" << std::endl;
        cout << "Size: " << size << endl;
        // Inputs
        //std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        //std::vector<double> x1 = randomDiscreteArray(batchSize, bound);
        //x1[0]=0.1;
        Plaintext text = loadtext(cc, size, 1024);
    	vector<Plaintext> tfidf = loadtfidf(cc, size, vocabsize, batchSize);
	    vector<Plaintext> idf = loadidf(cc, size, vocabsize, batchSize, false, 1023);
	    vector<Plaintext> querytf = loadquerytf(cc, size, 256, 1024, batchSize, 8); 
        usint dim = 1024/size;
        vector<Ciphertext<DCRTPoly>> c1(dim+1);
        c1[0] = cc->Encrypt(keys.publicKey, querytf[0]);
        for(usint i=0; i<dim;i++)c1[i+1] = cc->Encrypt(keys.publicKey, querytf[i]);

        // Encrypt the encoded vectors
        Plaintext result;

        for(usint i=0;i<iteration;i++){
            TIC(t);
            vector<Ciphertext<DCRTPoly>> doc = IDFMult(c1, size, idf);
            timeEval0[i]=TOC(t);
            cout << "TFIDF: " << doc.size() << ", Time: " << timeEval0[i] << ", Estimated level: " << doc[0]->GetLevel() << endl;

            TIC(t);
            vector<Ciphertext<DCRTPoly>> dist = DistanceComparison(doc, size, tfidf);
            timeEval1[i]=TOC(t);
            cout << "DistanceComparison: " << dist.size() << ", Time: " << timeEval1[i] << ", Estimated level: " << dist[2]->GetLevel() << endl;

            TIC(t);
            Ciphertext<DCRTPoly> c2 = Retrieval(dist[2], size, text);
            timeEval2[i]=TOC(t);
            timeEvalTotal[i]= timeEval0[i]+timeEval1[i]+timeEval2[i];
            cout << "Retrieval Time: " << timeEval2[i] << ", Total: " << timeEvalTotal[i] << ", Estimated level: " << c2->GetLevel() << endl;


            cc->Decrypt(keys.secretKey, c2, &result);    
            // writetext(result, size, "retrieved.txt", 1024);
            writetext(result, size, to_string(size)+to_string(i)+"retrievednumber.txt", 1024);
            mapandwritetext(result, size, to_string(size)+to_string(i)+"retrievedtext.txt", 1024);

            result->SetLength(16);
            cout << result << endl;
            cout << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
        }
        statTime(timeEval0, iteration);
        statTime(timeEval1, iteration);
        statTime(timeEval2, iteration);
        statTime(timeEvalTotal, iteration);

    } 




    void rotTest() {
        uint32_t multDepth = 10;
        uint32_t batchSize = 1 << 16;
        uint32_t scaleModSize = 35;


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
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        AddRotKeyForSort(keys.secretKey, cc, 4);

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! RotAndSum Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        //std::vector<double> x1 = randomDiscreteArray(batchSize, 128);
        //x1[0]=0.1;
        std::vector<double> x1 = fixedDiscreteArray(batchSize, 128);
        for(usint i=0;i<4;i++)x1[i]=(double)(i+1);
        for(usint i=4;i<16;i++)x1[i]=0.0;

        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(16);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

        // Encrypt the encoded vectors
        auto ciphertext = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        int32_t size=4;
        int32_t sizesquare=16;

	    vector<Plaintext> masks = maskPrecompute(size, batchSize, cc);
        ciphertext = cc->EvalMult(ciphertext,masks[1]);
        cc->ModReduceInPlace(ciphertext);

        auto c2=RotAndSum(ciphertext, -sizesquare, -size);
        cc->Decrypt(keys.secretKey, c2, &result);
        result->SetLength(16);
        cout << "copy row" << result << endl;

        auto c3=RotAndSum(c2, size, 1);
        cc->Decrypt(keys.secretKey, c3, &result);
        result->SetLength(16);
        cout << "col sum" << result << endl;

        c3=RotAndSum(c2, size*size, size);
        cc->Decrypt(keys.secretKey, c3, &result);
        result->SetLength(16);
        cout << "row sum" << result << endl;

        c2=RotAndSum(ciphertext, -(sizesquare-size), -(size-1));
        cc->Decrypt(keys.secretKey, c2, &result);
        result->SetLength(16);
        cout << "trans row" << result << endl;

        c2 = cc->EvalMult(c2,masks[0]);
        cc->ModReduceInPlace(c2);

        c3=RotAndSum(c2, sizesquare-size, size-1);
        cc->Decrypt(keys.secretKey, c3, &result);
        result->SetLength(16);
        cout << "trans col" << result << endl;

        c3=RotAndSum(c2, -size, -1);
        cc->Decrypt(keys.secretKey, c3, &result);
        result->SetLength(16);
        cout << "copy col" << result << endl;
    } 


    void SortTest(const uint32_t scaleModSize, const usint size, const int32_t arraybound) {
        TimeVar t;

        uint32_t multDepth = 58;
        uint32_t batchSize = 1 << 14;


        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        parameters.SetSecurityLevel(HEStd_NotSet);
        // /// Bootstrap block 1 ////
        // parameters.SetFirstModSize(scaleModSize+1);
        // parameters.SetScalingTechnique(FIXEDAUTO);
        

        //cout << "CKKS standard deviation " << parameters.GetStandardDeviation() << endl;
        //cout << "CKKS security level " <<  parameters.GetSecurityLevel() << endl;

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForSort(keys.secretKey, cc, size);
	    //bootSet2(cc, keys.secretKey, batchSize);


        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Sort Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        std::vector<double> x1(batchSize);
        x1 = fixedDiscreteArray(batchSize, arraybound);
        for(usint i=size;i<batchSize;i++)x1[i]=0.0;
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        for(usint i=0;i<1;i++){
            TIC(t);
            auto c2 = sort(c1, size, arraybound, scaleModSize, keys, false, false);
            auto timeEval = TOC(t);
            cc->Decrypt(keys.secretKey, c2, &result);
            //precision(result, batchSize);
            result->SetLength(size);
            cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            cout << "Time: " << timeEval << endl;
        }


    } 


    void SortFullTest(const uint32_t scaleModSize, const usint size, const int32_t arraybound) {
        TimeVar t;

        uint32_t multDepth = 58;
        uint32_t batchSize = 1 << 14;


        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        parameters.SetSecurityLevel(HEStd_NotSet);
        // /// Bootstrap block 1 ////
        // parameters.SetFirstModSize(scaleModSize+1);
        // parameters.SetScalingTechnique(FIXEDAUTO);
        

        //cout << "CKKS standard deviation " << parameters.GetStandardDeviation() << endl;
        //cout << "CKKS security level " <<  parameters.GetSecurityLevel() << endl;

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForSort(keys.secretKey, cc, size);
	    //bootSet2(cc, keys.secretKey, batchSize);


        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Sort Full Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        std::vector<double> x1(batchSize);
        x1 = fixedDiscreteArray(batchSize, arraybound);
        for(usint i=size;i<batchSize;i++)x1[i]=0.0;
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        for(usint i=0;i<1;i++){
            TIC(t);
            auto c2 = sort_full(c1, size, arraybound, scaleModSize, keys, false, false);
            auto timeEval = TOC(t);
            cc->Decrypt(keys.secretKey, c2, &result);
            //precision(result, batchSize);
            result->SetLength(size);
            cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            cout << "Time: " << timeEval << endl;
        }


    } 


    void kSorterTest(const uint32_t scaleModSize, const usint size, const int32_t arraybound, const usint k) {
        TimeVar t;

        uint32_t multDepth = 58;
        uint32_t batchSize = 1 << 14;


        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        parameters.SetSecurityLevel(HEStd_NotSet);
        // /// Bootstrap block 1 ////
        // parameters.SetFirstModSize(scaleModSize+1);
        // parameters.SetScalingTechnique(FIXEDAUTO);
        

        //cout << "CKKS standard deviation " << parameters.GetStandardDeviation() << endl;
        //cout << "CKKS security level " <<  parameters.GetSecurityLevel() << endl;

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        paramcheck(cc);

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForkSorter(keys.secretKey, cc, k);
	    //bootSet2(cc, keys.secretKey, batchSize);


        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Sort Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        std::vector<double> x1(batchSize);
        x1 = fixedDiscreteArray(batchSize, arraybound);
        //x1 = randomDiscreteArray(batchSize, arraybound);
        for(usint i=size;i<batchSize;i++)x1[i]=0.0;
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        for(usint i=0;i<1;i++){
            TIC(t);
            auto c2 = kSorter(c1, arraybound, k, size);
            auto timeEval = TOC(t);
            cc->Decrypt(keys.secretKey, c2, &result);
            //precision(result, batchSize);
            result->SetLength(size);
            cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            cout << "Time: " << timeEval << endl;
        }


    } 

    void SortIterTest(const uint32_t scaleModSize, const usint size, const int32_t arraybound) {
        TimeVar t;

        uint32_t multDepth = 2320/scaleModSize;
        usint logbatchSize = 16;
        uint32_t batchSize = 1 << logbatchSize;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(SPARSE_TERNARY);

        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        parameters.SetSecurityLevel(HEStd_NotSet);
        /// Bootstrap block 1 ////
        parameters.SetFirstModSize(scaleModSize+1);
        parameters.SetScalingTechnique(FLEXIBLEAUTO);

        //cout << "CKKS standard deviation " << parameters.GetStandardDeviation() << endl;
        //cout << "CKKS security level " <<  parameters.GetSecurityLevel() << endl;

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       
        //// bootblock2
        cc->Enable(FHE);
        usint levelBudgetElmt= 1 << (logbatchSize-13);
        std::vector<uint32_t> levelBudget = {levelBudgetElmt, levelBudgetElmt};
        cc->EvalBootstrapSetup(levelBudget);

        //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

        cout << "scaleModSize: " << scaleModSize << endl;
        paramcheck(cc);
        usint depth = FHECKKSRNS::GetBootstrapDepth(levelBudget, parameters.GetSecretKeyDist());
        cout << "bootdepth: " << depth << ", levelBudget: " << levelBudgetElmt << endl;
        cout << "budgetdepth: " << multDepth-depth << endl;

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        AddRotKeyForSort(keys.secretKey, cc, size);
	    //bootSet2(cc, keys.secretKey, batchSize);

        TIC(t);
        cc->EvalBootstrapKeyGen(keys.secretKey, batchSize);
        double timeEval0 =TOC(t);
        cout<<"Boot Keygen Done: "<< timeEval0 << "ms" << endl;


        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Sort Iterative Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        std::vector<double> x1(batchSize);
        x1 = fixedDiscreteArray(batchSize, arraybound);
        for(usint i=size;i<batchSize;i++)x1[i]=0.0;
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, depth);

        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        for(usint i=0;i<1;i++){
            TIC(t);
            c1 = cc->EvalBootstrap(c1);
            auto c2 = sort(c1, size, arraybound, scaleModSize, keys, true, true);
            auto timeEval = TOC(t);
            cc->Decrypt(keys.secretKey, c2, &result);
            //precision(result, batchSize);
            result->SetLength(size);
            cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            cout << "Time: " << timeEval << endl;
        }


    } 



void ptmodulusSwitchTest(const uint32_t scaleModSize) {

        uint32_t multDepth = 2320/scaleModSize;
        usint logbatchSize = 16;
        uint32_t batchSize = 1 << logbatchSize;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(SPARSE_TERNARY);

        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        parameters.SetSecurityLevel(HEStd_NotSet);
        /// Bootstrap block 1 ////
        parameters.SetFirstModSize(scaleModSize+1);
        parameters.SetScalingTechnique(FLEXIBLEAUTO);

        //cout << "CKKS standard deviation " << parameters.GetStandardDeviation() << endl;
        //cout << "CKKS security level " <<  parameters.GetSecurityLevel() << endl;

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        parameters.SetScalingModSize(scaleModSize+15);
        parameters.SetFirstModSize(scaleModSize+16);

        CryptoContext<DCRTPoly> ccboot = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       

        ccboot->Enable(PKE);
        ccboot->Enable(KEYSWITCH);
        ccboot->Enable(LEVELEDSHE);
        ccboot->Enable(ADVANCEDSHE);
        // cc->Enable(FHE);
        // usint levelBudgetElmt= 1 << (logbatchSize-13);
        // std::vector<uint32_t> levelBudget = {levelBudgetElmt, levelBudgetElmt};
        // cc->EvalBootstrapSetup(levelBudget);


        cout << "scaleModSize: " << cc->GetEncodingParams()->GetPlaintextModulus() << endl;
        cout << "scaleModSizeBoot: " << ccboot->GetEncodingParams()->GetPlaintextModulus() << endl;

        paramcheck(cc);
        // usint depth = FHECKKSRNS::GetBootstrapDepth(levelBudget, parameters.GetSecretKeyDist());
        // cout << "bootdepth: " << depth << ", levelBudget: " << levelBudgetElmt << endl;
        // cout << "budgetdepth: " << multDepth-depth << endl;

        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        //ccboot->InsertEvalMultKey(cc->);

        // TIC(t);
        // cc->EvalBootstrapKeyGen(keys.secretKey, batchSize);
        // double timeEval0 =TOC(t);
        // cout<<"Boot Keygen Done: "<< timeEval0 << "ms" << endl;


        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Sort Iterative Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        std::vector<double> x1(batchSize);
        x1 = randomIntArray(batchSize, 128);
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;
        cout << "sf: " << c1->GetScalingFactor() << endl;


        for(usint i=0;i<1;i++){
            //AdjustCipher(c1, 5);
            c1->SetScalingFactor(32*(c1->GetScalingFactor()));



           

            cc->Decrypt(keys.secretKey, c1, &result);
            //precision(result, batchSize);
            result->SetLength(8);
            cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            cout << "sf: " << c1->GetScalingFactor() << endl;

            // auto c2 = cc->EvalMult(c1, c1);
            // cc->ModReduceInPlace(c2);
            // //c1 = cc->EvalBootstrap(c1);
            // cc->Decrypt(keys.secretKey, c2, &result);
            // //precision(result, batchSize);
            // result->SetLength(8);
            // cout << result << " :: " << "\nEstimated level: " << result->GetLevel() << std::endl;
            // cout << "sf: " << c2->GetScalingFactor() << endl;

        }


    } 


}
