#include "openfhe.h"
#include "testcode.h"
#include "embedding.h"
#include "algorithms.h"

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

    void statTime(const vector<double> times, const usint iteration){
        double avg=0.0;
        double std=0.0;

        if(iteration!=1){
            for(long j=0;j<iteration;j++)avg+=times[j];
                avg/=iteration;
            for(long j=0;j<iteration;j++)std+=(times[j]-avg)*(times[j]-avg);
                std/=iteration;
                std=sqrt(std);
            cout << "Average time = " << avg << ", Std =" << std << endl;
        }else{
            cout << "Average time = " << times[0] << endl;
        }
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



}
