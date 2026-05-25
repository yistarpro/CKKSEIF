#include "openfhe.h"
#include "utils.h"
#include "algorithms.h"
#include "parity.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <map>
#include <omp.h>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {





Ciphertext<DCRTPoly> Parity(const Ciphertext<DCRTPoly> ciphertext, const usint d){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

    Ciphertext<DCRTPoly> sincipher = ParityBySin(ciphertext, d, 8);
    uint32_t ptmod = cc->GetCryptoParameters()->GetPlaintextModulus();
    usint iter = 1;
    if(ptmod < 41){
        if(d>6)iter+=1;
    }
    if(d>9)iter+=1;
    sincipher = Cleanse(sincipher, iter);
    return sincipher;
}


Ciphertext<DCRTPoly> ParityBySin(const Ciphertext<DCRTPoly> ciphertext, const usint d, const usint K){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    const double bound    = (double)(1 << (d - 1));
    const double halfPi   = M_PI / 2;
    const double div      = 1.0 / bound;
    Ciphertext<DCRTPoly> norm = cc->EvalSub(ciphertext, bound);
    norm = cc->EvalMult(norm, div);
    cc->ModReduceInPlace(norm);
    Ciphertext<DCRTPoly> coscipher = cc->EvalChebyshevFunction([halfPi](double x) -> double { return std::cos(x * halfPi); }, norm, -1, 1, K);
    Ciphertext<DCRTPoly> sincipher = cc->EvalChebyshevFunction([halfPi](double x) -> double { return std::sin(x * halfPi); }, norm, -1, 1, K);

    sincipher = cc->EvalMult(sincipher, coscipher);
    sincipher = cc->EvalAdd(sincipher, sincipher);
    cc-> ModReduceInPlace(sincipher);

    for(usint i=1; i<d-1;i++){

        coscipher = cc->EvalMult(coscipher,coscipher);
        cc-> ModReduceInPlace(coscipher);
        coscipher = cc->EvalAdd(coscipher,coscipher);
        coscipher = cc->EvalSub(coscipher,1);
        sincipher = cc->EvalMult(sincipher, coscipher);
        sincipher = cc->EvalAdd(sincipher, sincipher);
        cc-> ModReduceInPlace(sincipher);

    }
    sincipher = cc->EvalMult(sincipher,sincipher);
    cc-> ModReduceInPlace(sincipher);
    //sincipher = cc->EvalPoly(sincipher, {0,0,4,-3});

    return sincipher;
}


Ciphertext<DCRTPoly> ExtractMSB(const Ciphertext<DCRTPoly> ciphertext, const usint bound){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = cc->EvalAdd(ciphertext, 0.5);
    result = cc->EvalMult(result, 2/((double)bound)); 
    cc->ModReduceInPlace(result);
    result = cc->EvalSub(result, 1); 
    result = compandUp(result, bound, false,  log2(bound)-1);

    return result;

}

Ciphertext<DCRTPoly> ExtractLSB(const Ciphertext<DCRTPoly> ciphertext, const usint bound){
    usint logbound = log2(bound);
    // if(bound<64)logbound = 6;
    Ciphertext<DCRTPoly> result = ParityBySin(ciphertext, logbound, 8);
    return result;

}

vector<Ciphertext<DCRTPoly>> ExtractMSBs(const Ciphertext<DCRTPoly> ciphertext, const usint bound, usint iter){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> tmp = ciphertext->Clone();
    usint boundbits = log2(bound);
    usint boundtmp = bound;
    if(boundbits < iter)iter = boundbits;
    vector<Ciphertext<DCRTPoly>> result(iter);
    for(usint i=0; i< iter; i++){
        result[iter-i-1] = ExtractMSB(tmp, boundtmp);
        tmp = cc->EvalSub(tmp, result[iter-i-1]);
        result[iter-1-i] = cc->EvalMult(result[iter-1-i], 2/((double)(boundtmp)));
        cc->ModReduceInPlace(result[iter-1-i]);
        if(i>0 && boundtmp <512)result[iter-1-i] =Cleanse(result[iter-1-i],1); //precision correction for scaling factor =50
        //Cleanse
        boundtmp /=2;
        std::cout << "Estimated level: " << result[iter-1-i]->GetLevel() << std::endl;

        //if(???)cc->EvalBootstrap();
    }

    return result;
}


vector<Ciphertext<DCRTPoly>> ExtractLSBs(const Ciphertext<DCRTPoly> ciphertext, const usint bound, usint iter){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> tmp = ciphertext->Clone();
    usint boundbits = log2(bound);
    usint boundtmp = bound;
    if(boundbits < iter)iter = boundbits;
    vector<Ciphertext<DCRTPoly>> result(iter);
    for(usint i=0; i< iter; i++){
        result[i] = ExtractLSB(tmp, boundtmp);
        result[i] = BootAuto(result[i]);
        //result[i] = Cleanse(result[i],1); //Maximize Output detph
        if(i!=iter-1){
            tmp = cc->EvalSub(tmp, result[i]);
            tmp = cc->EvalMult(tmp, 0.5);
            cc->ModReduceInPlace(tmp);
            boundtmp /=2;
        }
        result[i] = Cleanse(result[i],2);
        std::cout << "Estimated level: " << result[i]->GetLevel() << std::endl;
    }

    return result;
}

// Budget-aware bit decomposition. Extracts the `boundbits`-bit binary
// representation of an encrypted value as a vector of `boundbits` ciphertexts.
// Strategy: interleave LSB extraction (cheap, sinc-based) and MSB extraction
// (deeper, compandUp-based) so the total mult depth stays under `maxdepth`.
// The two budget tables encode the per-bit-count depth cost of one round:
//   MSBbudget[k] = depth cost of one ExtractMSB on a k-bit value
//   LSBbudget[k] = depth cost of one ExtractLSB on a k-bit value
// (index 0 and 1 are unused since the trivial 1-bit case is handled separately).
vector<Ciphertext<DCRTPoly>> DecompToBits(const Ciphertext<DCRTPoly> ciphertext, const usint boundbits, const usint maxdepth){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> tmp = ciphertext->Clone();
    vector<Ciphertext<DCRTPoly>> result(boundbits);
    usint currentbits = boundbits;     // bits left to extract
    usint LSBptr = 0;
    usint MSBptr = boundbits - 1;
    const vector<usint> MSBbudget = {0, 0, 17, 17, 17, 21, 21, 25, 25, 29, 29};
    const vector<usint> LSBbudget = {0, 0, 10, 11, 12, 13, 14, 15, 16, 17, 20};

    while(currentbits){
        usint currentbound = 1<< currentbits;

        if(currentbits > 1){
            usint budget = maxdepth - (tmp->GetLevel());
            usint tmpbits = currentbits;
            usint boundtmp= currentbound;
            usint iter = 0;
            Ciphertext<DCRTPoly> tmp2 = tmp->Clone();
            //LSB
            while(budget > LSBbudget[tmpbits] && tmpbits > 1){
                result[LSBptr] = ExtractLSB(tmp2, boundtmp);
                tmpbits-=1;
                budget-=LSBbudget[tmpbits];
                boundtmp/=2;
                tmp2 = cc->EvalSub(tmp2, result[LSBptr]);
                tmp2 = cc->EvalMult(tmp2, 0.5);
                cc->ModReduceInPlace(tmp2);
                LSBptr+=1;
                iter+=1;
                
                std::cout << "Estimated level: " << tmp2->GetLevel() << std::endl;
                std::cout << "Estimated budget: " << budget << std::endl;
            }
            if(iter!=0){
                tmp2 = cc->EvalMult(tmp2, (double)(1<<iter));
                cc->ModReduceInPlace(tmp2);
            }
            
            //MSB
            budget = maxdepth - (tmp->GetLevel());
            tmpbits = currentbits;
            boundtmp= currentbound;
            currentbits-=iter;
            while(budget > MSBbudget[tmpbits] && currentbits > 1){
                result[MSBptr] = ExtractLSB(tmp, boundtmp);
                tmp = cc->EvalSub(tmp, result[MSBptr]);
                tmp2 = cc->EvalSub(tmp2, result[MSBptr]);
                result[MSBptr] = cc->EvalMult(result[MSBptr], 2/((double)(boundtmp)));
                cc->ModReduceInPlace(result[MSBptr]);
                // if(i>0 && boundtmp <512)result[iter-1-i] =Cleanse(result[iter-1-i],1); //precision correction for scaling factor =50
                boundtmp /=2;
                currentbits-=1;
                budget-=MSBbudget[tmpbits];
                tmpbits-=1;
                MSBptr-=1;
                std::cout << "Estimated level: " << tmp->GetLevel() << std::endl;
                std::cout << "Estimated level: " << tmp2->GetLevel() << std::endl;
                std::cout << "Estimated budget: " << budget << std::endl;
            }
            if(iter!=0){
                tmp = cc->EvalMult(tmp2, 1/(double)(1<<iter));
                cc->ModReduceInPlace(tmp);
            }else{
                tmp = tmp2->Clone();
            }
        }

        if(currentbits==1){
            result[LSBptr] = tmp;
            currentbits-=1;
        }else{
            tmp = cc->EvalBootstrap(tmp);
            std::cout << "Estimated level: " << tmp->GetLevel() << std::endl;
        }
        

    }

    return result;
}



vector<Ciphertext<DCRTPoly>> BitsToOHE(const vector<Ciphertext<DCRTPoly>> ciphertext){
    const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
    usint num = ciphertext.size();
    vector<Ciphertext<DCRTPoly>> result(2*num);

    for(usint i=0;i< num ; i++){
        result[2*i]=cc->EvalSub(ciphertext[i], 1);
        cc->EvalNegateInPlace(result[2*i]);
        result[2*i+1] = ciphertext[i]->Clone();
        
    }
    return result;
}

vector<Ciphertext<DCRTPoly>> BitsToOHESIMD(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint size){
    const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
    uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    usint num = ciphertext.size();
    vector<Ciphertext<DCRTPoly>> result(num);
    Ciphertext<DCRTPoly> tmp;

    Plaintext pt = GenEEFCheckerIntervalRecursive(0, 2, size, cc);


    for(usint i=0;i< num ; i++){
        result[i] = RotSum(ciphertext[i], -batchSize, -2*size);
        tmp = cc->EvalSub(ciphertext[i], pt);
        cc->EvalNegateInPlace(tmp);
        result[i] = cc->EvalRotate(result[i], size);
        cc->EvalAddInPlace(result[i],tmp);        
    }
    return result;
}



// compandUp — sign-function approximation used by ExtractMSB / ExtractLSB.
// Brought here from the pre-reorg core (algorithms.cpp). Parity-specific.
Ciphertext<DCRTPoly> compandUp(const Ciphertext<DCRTPoly> ciphertext, const double bound, const bool boot,  const usint up){
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    
    usint degg=2;
    usint logbound=log2(bound);
    if(logbound>5)degg+=1;
    if(logbound>7)degg+=1;
    if(logbound>9)degg+=1;

    usint degf=2;

    vector<Ciphertext<DCRTPoly>> powers(3);


    for(usint i=0;i<degg;i++){
        powers[0]=cc->EvalMult(result, result);
        cc->ModReduceInPlace(powers[0]);
        powers[1]=cc->EvalMult(powers[0], powers[0]);
        cc->ModReduceInPlace(powers[1]);
        powers[0]=cc->EvalMult(powers[0], result);
        cc->ModReduceInPlace(powers[0]);
        powers[2]=cc->EvalMult(powers[1], powers[0]);
        cc->ModReduceInPlace(powers[2]);
        powers[1]=cc->EvalMult(powers[1], result);
        cc->ModReduceInPlace(powers[1]);

        result=cc->EvalMult(result, 4.4814453125);
        powers[0]=cc->EvalMult(powers[0], -16.1884765625);
        powers[1]=cc->EvalMult(powers[1], 25.013671875);
        powers[2]=cc->EvalMult(powers[2], -12.55859375);
        result = cc-> EvalAdd(result,powers[0]);
        result = cc-> EvalAdd(result,powers[1]);
        result = cc-> EvalAdd(result,powers[2]);
        cc->ModReduceInPlace(result);
    }

    if(boot)result = cc->EvalBootstrap(result);

    for(usint i=0;i<degf;i++){
        powers[0]=cc->EvalMult(result, result);
        cc->ModReduceInPlace(powers[0]);
        powers[1]=cc->EvalMult(powers[0], powers[0]);
        cc->ModReduceInPlace(powers[1]);
        powers[0]=cc->EvalMult(powers[0], result);
        cc->ModReduceInPlace(powers[0]);
        powers[2]=cc->EvalMult(powers[1], powers[0]);
        cc->ModReduceInPlace(powers[2]);
        powers[1]=cc->EvalMult(powers[1], result);
        cc->ModReduceInPlace(powers[1]);

        if(i==degf-1 && up != 1){
            double upscale = (double)(1 << up);
            result=cc->EvalMult(result, 1.09375*upscale);
            powers[0]=cc->EvalMult(powers[0], -1.09375*upscale);
            powers[1]=cc->EvalMult(powers[1], 0.65625*upscale);
            powers[2]=cc->EvalMult(powers[2], -0.15625*upscale);
            result = cc-> EvalAdd(result,powers[0]);
            result = cc-> EvalAdd(result,powers[1]);
            result = cc-> EvalAdd(result,powers[2]);
            cc->ModReduceInPlace(result);
            result = cc-> EvalAdd(result, 0.5*upscale);
        }else{
            result=cc->EvalMult(result, 2.1875);
            powers[0]=cc->EvalMult(powers[0], -2.1875);
            powers[1]=cc->EvalMult(powers[1], 1.3125);
            powers[2]=cc->EvalMult(powers[2], -0.3125);
            result = cc-> EvalAdd(result,powers[0]);
            result = cc-> EvalAdd(result,powers[1]);
            result = cc-> EvalAdd(result,powers[2]);
            cc->ModReduceInPlace(result);
        }

    }


    return result;
}

}
