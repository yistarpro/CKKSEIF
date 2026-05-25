#include "openfhe.h"
#include "utils.h"
#include "embedding.h"
#include "algorithms.h"
#include "counting.h"
#include <iostream>
#include <vector>
#include <cmath>
// #include "openfhecore.h"
// #include "math/chebyshev.h"
#include <map>
#include <omp.h>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {
    // HECount §4.3 — rotation keys for the information-retrieval pipeline.
    void AddRotKeyForIR(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t size, const int32_t batchSize){
        int32_t copy=batchSize;
        std::vector<int32_t> arr(2*log2(batchSize));
        for(long i = 0 ; i < log2(batchSize) ; i++){
            copy >>= 1;
            arr[i]=(copy);
            arr[log2(batchSize)+i]=-(copy);
        }
        cc->EvalRotateKeyGen(privateKey, arr);

        std::vector<int32_t> arr2(size-1);
        for(long i = 1 ; i < size ; i++){
            arr2[i-1]=-(i);
        }
        cc->EvalRotateKeyGen(privateKey, arr2);

    }

    // HECount §3.4 — rotation keys for the SIMD-parallel counting pipeline.
    void AddRotKeyForCountSIMD(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const usint base, const int32_t size, const int32_t batchSize, const usint bound){
        usint paral = 0;
        usint tmpnum = batchSize/size;
        while(true){
            if(tmpnum % base == 1){
                break;
            }else{
                if(tmpnum % base == 0){
                    tmpnum /=base;
                    paral+=1;
                }else{
                    abort();
                }
            }
        }

        usint newbase = batchSize/size;
        if(bound/newbase < newbase)newbase = bound/newbase;
        cout << "Parallelization by " << paral << ", maximal rotkey for parallelization: " << newbase <<endl;
        if(newbase > 1){
            std::vector<int32_t> arr(newbase-1);
            for(long i = 1 ; i < newbase ; i++){
                arr[i-1]=(size*i);
            }
            cc->EvalRotateKeyGen(privateKey, arr);
        }
    }





    // HECount §3.3 / Alg 3 — DimDecomp: dimension-decomposition map for tensor-product basis expansion.
    vector<vector<usint>> DimDecomp(const usint exponent, const usint exponentbound, const bool maximalmode){
        vector<vector<usint>> divisions(exponent);
        usint numofresult=1;

        
        if(exponent==1){
            divisions[0]={1};
            return divisions;
        }

        if(exponentbound!=0){
            for(usint l=0; l< exponent/exponentbound ; l++){
                divisions[0].push_back(exponentbound);
            }
            if(exponent%exponentbound!=0)divisions[0].push_back(exponent%exponentbound);
        }else{
            divisions[0]={exponent};
        }
    
        // cout << "level: " << 0 << ", entries: " << divisions[0] << endl;

        if(divisions[0].size()==1 && maximalmode==false){
            divisions[0]={exponent/2, exponent - exponent/2};
        }

        for(usint l=1;l<exponent;l++){
            if(divisions[l-1].size()==exponent)break;

            numofresult+=1;
            for(usint i=0;i<divisions[l-1].size();i++){
                usint entry = divisions[l-1][i];
                if(entry==1){
                    divisions[l].push_back(1);
                }else{
                    divisions[l].push_back(entry/2);
                    divisions[l].push_back(entry - entry/2);
                }
            }
            // cout << "level: " << l << ", entries: " << divisions[l] << endl;
        }
        //Flip
        vector<vector<usint>> result(numofresult);
        for(usint l=0;l<numofresult;l++){
            //result[l]=divisions[divisions.size()-1-l];
            result[numofresult-1-l]=divisions[l];

        }

        return result;

    }


    // HECount §3.3 / Alg 4 (sub-procedure) — single-round tensor product between two p-bases.
    vector<Ciphertext<DCRTPoly>> BasisExpBlock(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint level, vector<vector<usint>> indices, const bool maximalmode){
        const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
        usint partitionnum = indices[level].size();

        usint currentcipherptr = 0;
        usint cipherptr = 0;
        usint currentpartitionptr = 0;

        if(partitionnum==1 && maximalmode==false)return ciphertext;

        usint res=0;
        for(usint i=0; i<partitionnum; i++){
            res+=pow(base, indices[level][i]);
        }

        vector<Ciphertext<DCRTPoly>> result(res);
        vector<Ciphertext<DCRTPoly>> tmp(2);

        for(usint i=0;i< partitionnum ; i++){
            if(indices[level-1][currentpartitionptr]==indices[level][i]){
                for(usint j=0; j<pow(base, indices[level][i]); j++){
                    result[cipherptr+j]=ciphertext[currentcipherptr+j]->Clone();
                }
                cipherptr+=pow(base, indices[level][i]);
                currentcipherptr+=pow(base, indices[level][i]);
                currentpartitionptr+=1;
            }else{
                usint lowerbase = pow(base, indices[level-1][currentpartitionptr]);
                for(usint j=0; j<pow(base, indices[level][i]); j++){
                    
                    usint upper = j/lowerbase;
                    usint lower = j%lowerbase;

                    tmp[0]=ciphertext[currentcipherptr+lower]->Clone();
                    tmp[1]=ciphertext[currentcipherptr+lowerbase+upper]->Clone();
                    tmp[0] = cc->EvalMult(tmp[0],tmp[1]);
                    cc->ModReduceInPlace(tmp[0]);
                    //result[cipherptr+j] = Cleanse(tmp[0],1);
                    result[cipherptr+j]=tmp[0]->Clone();
                }
                cipherptr+=pow(base, indices[level][i]);
                currentcipherptr+=pow(base, indices[level-1][currentpartitionptr]);
                currentcipherptr+=pow(base, indices[level-1][currentpartitionptr+1]);
                currentpartitionptr+=2;
            }  
        }


        return result;
    }




    // HECount §3.3 / Alg 4 — full Basis Expansion driven by the DimDecomp schedule.
    vector<Ciphertext<DCRTPoly>> BasisExp(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint exponentbound, const bool maximalmode){
        usint exponent = ciphertext.size()/base;
        vector<vector<usint>> indices = DimDecomp(exponent, exponentbound, maximalmode);
        vector<Ciphertext<DCRTPoly>> tmp;

        if(exponentbound==1 || indices.size()==1){
            return ciphertext;
        }else{
            tmp = BasisExpBlock(ciphertext, base, 1, indices, maximalmode);
            // cout << "Step 0: " << tmp.size() << " ciphertexts, " << indices[1] <<endl;
        }

        for(usint i=1;i<indices.size()-1;i++){
            tmp = BasisExpBlock(tmp, base, i+1, indices, maximalmode);
            // cout << "Step " << i << ": " << tmp.size() <<  " ciphertexts, " << indices[i+1] <<endl;

        }
        
        return tmp;
    }




    // HECount §3.4 — SIMD-packed one-hot encoding materialization.
    vector<Ciphertext<DCRTPoly>> ToOHESIMD(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size){
        const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
        usint num = ciphertext.size();
        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        usint paral = 0;
        usint tmpnum = batchSize/size;
        while(true){
            if(tmpnum % base == 1){
                break;
            }else{
                if(tmpnum % base == 0){
                    tmpnum /=base;
                    paral+=1;
                }else{
                    abort();
                }
            }
        }
        vector<Plaintext> ptxts = GenIndicatorCheckerForSIMDCOUNT(base, size, paral, cc);


        vector<Ciphertext<DCRTPoly>> result(num);
        vector<usint> rounds = ParamEEF(base, cc->GetCryptoParameters()->GetPlaintextModulus());

        for(usint i=0;i< num ; i++){
            result[i]=EEFSIMD(ciphertext[i], base, rounds, ptxts[i%paral]);
            
        }
        return result;
    }


    // HECount §3.4 / Alg 6 (sub-procedure) — parallel tensor product between two full-bases.
    vector<Ciphertext<DCRTPoly>> ParalBasisExpBlock(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size, const usint paral, const usint leftover, const usint level, vector<vector<usint>> indices, const bool maximalmode){
        const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
        usint partitionnum = indices[level].size();

        usint currentcipherptr = 0;
        usint cipherptr = 0;
        usint currentpartitionptr = 0;

        if(partitionnum==1 && maximalmode==false)return ciphertext;

        usint res=0;
        usint newbase = pow(base, paral);
        usint leftbase = pow(base, leftover);

        vector<usint> powedindices(partitionnum);
        for(usint i=0; i<partitionnum; i++){
            if(leftover!=0 && i==partitionnum-1){
                if(indices[level][i]==1){
                    powedindices[i]=1;
                }else{
                    powedindices[i]=pow(newbase, indices[level][i]-2)*leftbase;
                }
                res+=powedindices[i];
            }else{
                powedindices[i]=pow(newbase, indices[level][i]-1);
                res+=powedindices[i];
            }
        }
        // cout << powedindices << endl;

        usint pastpartitionnum = indices[level-1].size();
        vector<usint> pastpowedindices(pastpartitionnum);
        for(usint i=0; i<pastpartitionnum; i++){
            if(leftover!=0 && i==pastpartitionnum-1){
                if(indices[level-1][i]==1){
                    pastpowedindices[i]=1;
                }else{
                    pastpowedindices[i]=pow(newbase, indices[level-1][i]-2)*leftbase;
                }
            }else{
                pastpowedindices[i]=pow(newbase, indices[level-1][i]-1);
            }
        }
        // cout << pastpowedindices << endl;

        vector<Ciphertext<DCRTPoly>> result(res);
        vector<Ciphertext<DCRTPoly>> tmp(3);

        for(usint i=0;i< partitionnum ; i++){
            if(indices[level-1][currentpartitionptr]==indices[level][i]){
                for(usint j=0; j<powedindices[i]; j++){
                    // cout <<" gen " << cipherptr+j << "from " << currentcipherptr+j << endl;

                    result[cipherptr+j]=ciphertext[currentcipherptr+j]->Clone();
                }
                cipherptr+=powedindices[i];
                currentcipherptr+=powedindices[i];
                currentpartitionptr+=1;
            }else{
                cout << "tensoring " << pastpowedindices[currentpartitionptr] << ", " << pastpowedindices[currentpartitionptr+1] << " to " << powedindices[i] << endl;

                for(usint j=0; j<pastpowedindices[currentpartitionptr]; j++){
                    tmp[0]=ciphertext[currentcipherptr+j]->Clone();
                    for(usint k=0; k<pastpowedindices[currentpartitionptr+1]; k++){
                        tmp[1]=ciphertext[currentpartitionptr+pastpowedindices[currentpartitionptr]+k]->Clone();
                        usint rotidx = newbase;
                        if(leftover!=0 && i == partitionnum-1 &&  indices[level-1][currentpartitionptr+1]==1)rotidx=leftbase;
                        
                        for(usint l=0; l<rotidx; l++){
                            if(l==0){
                                tmp[2] = tmp[1]->Clone();
                            }else{
                                tmp[2] = cc->EvalRotate(tmp[1], size*l);
                            }
                            tmp[0] = cc->EvalMult(tmp[0],tmp[2]);
                            cc->ModReduceInPlace(tmp[0]);
                            // cout <<" gen " << cipherptr+j*pastpowedindices[currentpartitionptr+1]*rotidx+k*rotidx+l << endl;
                            result[cipherptr+j*pastpowedindices[currentpartitionptr+1]*rotidx+k*rotidx+l]=tmp[0]->Clone();
                        }
                    }
                }
                cipherptr+=powedindices[i];
                currentcipherptr+=pastpowedindices[currentpartitionptr];
                currentcipherptr+=pastpowedindices[currentpartitionptr+1];
                currentpartitionptr+=2;
            }  
        }


        return result;
    }


    // HECount §3.4 / Alg 6 — Parallelized Basis Expansion.
    vector<Ciphertext<DCRTPoly>> ParalBasisExp(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size, const usint exponentbound, const bool maximalmode){
        usint exponent = ciphertext.size();
        const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();

        usint paral = 0;
        usint tmpnum = batchSize/size;
        while(true){
            if(tmpnum % base == 1){
                break;
            }else{
                if(tmpnum % base == 0){
                    tmpnum /=base;
                    paral+=1;
                }else{
                    abort();
                }
            }
        }
        usint newexponent = exponent/paral;
        vector<Ciphertext<DCRTPoly>> fullbasis(newexponent);
        vector<Ciphertext<DCRTPoly>> multtmp(paral);
        for(usint i=0; i< newexponent; i++){
            for(usint j=0; j<paral;j++){
                multtmp[j] = ciphertext[i*paral+j]->Clone(); 
            }
            fullbasis[i]=Product(multtmp);
        }
        usint leftover = exponent% paral;
        if(leftover!=0){
            vector<Ciphertext<DCRTPoly>> multtmp2(leftover);
            for(usint j=0; j<leftover;j++){
                multtmp2[j] = ciphertext[newexponent*paral+j]->Clone(); 
            }
            Ciphertext<DCRTPoly> leftbasis=Product(multtmp2);
            fullbasis.push_back(leftbasis);
            newexponent+=1;
        }
        cout << "Full basis Done, level: " << fullbasis[0]->GetLevel() << ", num of fullbasis: " << newexponent << endl; 


        vector<vector<usint>> indicestmp = DimDecomp(newexponent, exponentbound, maximalmode);
        vector<Ciphertext<DCRTPoly>> tmp;
        // cout << "Start: " << ciphertext.size() <<endl;
        vector<vector<usint>> indices(indicestmp.size());
        for(usint l=0;l<indicestmp.size();l++){
            vector<usint> tmpind(indicestmp[l].size());
            for(usint i=0;i<indicestmp[l].size();i++){
                tmpind[i]=indicestmp[l][indicestmp[l].size()-1-i];
            }
            indices[l]=tmpind;
        }

        if(exponentbound==1 || indices.size()==1){
            return fullbasis;
        }else{
            tmp = ParalBasisExpBlock(fullbasis, base, size, paral, leftover, 1, indices, maximalmode);
            // cout << "Step 0: " << tmp.size() << " ciphertexts, " << indices[1] <<endl;
        }

        for(usint i=1;i<indices.size()-1;i++){
            tmp = ParalBasisExpBlock(tmp, base, size, paral, leftover, i+1, indices, maximalmode);
            // cout << "Step " << i << ": " << tmp.size() <<  " ciphertexts, " << indices[i+1] <<endl;
        }
        
        return tmp;
    }




    // HECount §3.2 — non-SIMD one-hot encoding materialization.
    vector<Ciphertext<DCRTPoly>> ToOHE(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base){
        const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
        usint num = ciphertext.size();
        vector<Ciphertext<DCRTPoly>> result(base*num);
        vector<usint> rounds = ParamEEF(base, cc->GetCryptoParameters()->GetPlaintextModulus());

        for(usint i=0;i< num ; i++){
            for(usint j=0; j<base; j++){
                result[base*i+j]=EEF(ciphertext[i],base, rounds, j);
            }    
        }
        return result;
    }



        
    // HECount §3.2 / Alg 2 — Count: coded counting (the main proposal); also covers Alg 5 CountEB via expanded-basis input.
    vector<Ciphertext<DCRTPoly>> Count(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const usint gather){
        const CryptoContext<DCRTPoly> cc = basis[0]->GetCryptoContext();
        vector<vector<usint>> indices = DimDecomp(exponent, exponentbound);
        vector<usint> currentindices= indices[indices.size()-1];


        usint multnum = currentindices.size();
        vector<usint> bases(multnum);
        usint bound = 1;
        for(usint i=0; i<multnum;i++){
            bases[i]=pow(base, currentindices[i]);
            bound*=bases[i];
        }
        cout << "bound: " << bound << ", Multiplication num: " << multnum << ", Count Indices: " << currentindices << endl;

        usint ridx=1;
        usint gatheridx=0;
        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        vector<double> maskmsg(batchSize);
        maskmsg[0]=1;
        Plaintext mask= cc->MakeCKKSPackedPlaintext(maskmsg);;
        if(gather!=0){
            ridx=0;
            gatheridx=bound/gather;
            if(bound%gather!=0)gatheridx+=1;
            // for(usint i=1;i<batchSize;i++){
            //     maskmsg[i]=0.0;
            // }
        }
        

        vector<Ciphertext<DCRTPoly>> multVec(multnum);
        vector<Ciphertext<DCRTPoly>> result((bound-1)*ridx+1+gatheridx);
        cout << "Num of Result: " << (bound-1)*ridx+1+gatheridx << endl;
        //If gather==false : idx=1, num of result: bound
        //If gather==true : idx=0, num of result: gatheridx+1



        for(usint i=0; i<bound; i++){
            usint val = i;
            usint idx = 0;
            // cout << "val: " << val;
            for(usint j=0; j<multnum;j++){
                usint tmp = val%bases[j];
                // cout << ", " << tmp;
                val/=bases[j];
                multVec[j]=basis[idx+tmp]->Clone();
                idx+=bases[j];
            }
            // cout << endl;

            result[i*ridx]=Product(multVec);
            //Cleanse
            result[i*ridx]=RotSum(result[i*ridx], size ,1);

            if(gather!=0){
                result[0] = cc->EvalMult(result[0], mask);
                if(i%gather==0){
                    result[i/gather+1]= result[0]->Clone();
                }else{
                    // result[0] = RotSlowMinus(result[0], (i%gather), gather);
                    result[0] = cc-> EvalRotate(result[0], -(i%gather));
                    result[i/gather+1]= cc->EvalAdd(result[i/gather+1],result[0]);
                }            
            }
        }
        
        if(gather!=0){
            for(usint i=1;i<gatheridx+1;i++)cc->ModReduceInPlace(result[i]);
        }

        return result;
    }

    // HECount §3.4 / Alg 7 — ParalCount: parallelized coded counting using FullBasis.
    vector<Ciphertext<DCRTPoly>> ParalCount(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint rotsumsize, const usint exponent){
        const CryptoContext<DCRTPoly> cc = basis[0]->GetCryptoContext();
        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();


        usint paral = 0;
        usint tmpnum = batchSize/size;
        while(true){
            if(tmpnum % base == 1){
                break;
            }else{
                if(tmpnum % base == 0){
                    tmpnum /=base;
                    paral+=1;
                }else{
                    abort();
                }
            }
        }
        usint newexponent = exponent/paral;
        usint leftover = exponent% paral;
        if(leftover!=0)newexponent+=1;
        vector<vector<usint>> indices = DimDecomp(newexponent, 0, false);
        vector<usint> tmpindices= indices[indices.size()-1];
        usint partitionnum = tmpindices.size();
        vector<usint> currentindices(partitionnum);
        for(usint i=0;i<partitionnum;i++)currentindices[i]=tmpindices[partitionnum-1-i];

        if(partitionnum > 2){
            abort();
        }


        usint newbase = pow(base, paral);
        usint leftbase = pow(base, leftover);
        // usint partitionnum = currentindices.size();

        vector<usint> powedindices(partitionnum);
        for(usint i=0; i<partitionnum; i++){
            if(leftover!=0 && i==partitionnum-1){
                if(currentindices[i]==1){
                    powedindices[i]=1;
                }else{
                    powedindices[i]=pow(newbase, currentindices[i]-2)*leftbase;
                }
            }else{
                powedindices[i]=pow(newbase, currentindices[i]-1);
            }
        }
        // cout << powedindices << endl;


        if(partitionnum==1){
            usint restmp=powedindices[0];
            cout << "res num: " << restmp  << ", Multiplication num: " << partitionnum << ", Count Indices: " << currentindices << endl;
            vector<Ciphertext<DCRTPoly>> resulttmp(restmp);

            for(usint i =0;i<restmp;i++){
                resulttmp[i]=RotSum(basis[i], rotsumsize ,1);
            }
            return resulttmp;
        }

        usint rotidx = newbase;
        if(leftover!=0 && powedindices[1]==1)rotidx=leftbase;
        
        usint res=powedindices[0]*powedindices[1]*rotidx;

        cout << "res num: " << res  << ", Multiplication num: " << partitionnum << ", Count Indices: " << currentindices << endl;


        vector<Ciphertext<DCRTPoly>> multVec(partitionnum);
        vector<Ciphertext<DCRTPoly>> result(res);
        vector<Ciphertext<DCRTPoly>> tmp(3);




        for(usint j=0; j<powedindices[0]; j++){
            tmp[0]=basis[j]->Clone();
            // cout << j << endl;
            for(usint k=0; k<powedindices[1]; k++){

                tmp[1]=basis[powedindices[0]+k]->Clone();
                
                // cout << "tensoring " << rotidx << ", idx " << j*powedindices[1]*rotidx+k*rotidx << endl;
                for(usint l=0; l<rotidx; l++){
                    if(l==0){
                        tmp[2] =tmp[1]->Clone();
                    }else{
                        // cout << size*l << endl;
                        tmp[2] = cc->EvalRotate(tmp[1], (size*l));
                    }
                    tmp[0] = cc->EvalMult(tmp[0],tmp[2]);
                    cc->ModReduceInPlace(tmp[0]);
                    tmp[0]=RotSum(tmp[0], rotsumsize ,1);
                    // cout << "gen " << j*powedindices[1]*rotidx+k*rotidx+l << endl;
                    result[j*powedindices[1]*rotidx+k*rotidx+l]=tmp[0]->Clone();
                }
            }
        }    

        return result;
    }


    // HECount §4.2 — Build the n-gram basis from per-token bases.
    vector<Ciphertext<DCRTPoly>> NgramBasis(const vector<Ciphertext<DCRTPoly>> basis, const usint n){
        usint basissize=basis.size();
        vector<Ciphertext<DCRTPoly>> result(n*basissize);
        const CryptoContext<DCRTPoly> cc = basis[0]->GetCryptoContext();


        for(usint i=0;i<basissize;i++){
            result[i]=basis[i]->Clone();
        }
        for(usint j=1;j<n;j++){
            for(usint i=0;i<basissize;i++){
                result[i+j*basissize]=cc->EvalRotate(basis[i], -j);
            }
        }

        return result;
    }


    // HECount §4.2 / Fig. 2 — Ngram: count occurrences of length-n token sequences.
    vector<Ciphertext<DCRTPoly>> Ngram(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const usint n, const double ratio, const bool maximalmode){
        const CryptoContext<DCRTPoly> cc = basis[0]->GetCryptoContext();
        vector<vector<usint>> indices = DimDecomp(exponent, exponentbound, maximalmode);
        vector<usint> currentindices= indices[indices.size()-1];
        usint indicessize = currentindices.size();

        usint multnum = n*currentindices.size();
        vector<usint> bases(multnum);
        usint bound = 1;
        for(usint i=0; i<multnum;i++){
            bases[i]=pow(base, currentindices[i%indicessize]);
            bound*=bases[i];
        }

        double partialbounddouble = ((double)bound * ratio) / 100.0;
        usint partialbound = (usint)partialbounddouble;

        usint printedratio = ratio;
        if(partialbound > bound || partialbound == 0){
            partialbound=bound;
            printedratio=100;
        }
        cout << "bound: " << bound << ", Multiplication num: " << multnum << ", Count Indices: " << currentindices << ", " << n <<"-gram Count of ratio" << printedratio << "%, partial bound: " << partialbound << endl;


        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        vector<double> maskmsg(batchSize);
        for(usint i=1;i<batchSize;i++){
            maskmsg[i]=0.0;
        }
        for(usint i=0;i<n-1;i++){
            maskmsg[i]=1;
        }
        Plaintext mask = cc->MakeCKKSPackedPlaintext(maskmsg);

        

        vector<Ciphertext<DCRTPoly>> multVec(multnum);
        vector<Ciphertext<DCRTPoly>> result(1); //For Test, does not require saving result.
        //vector<Ciphertext<DCRTPoly>> result(bound);



        for(usint i=0; i<partialbound; i++){
            usint val = i;
            usint idx = 0;
            // cout << "val: " << val;
            for(usint j=0; j<multnum;j++){
                usint tmp = val%bases[j];
                // cout << ", " << tmp;
                val/=bases[j];
                multVec[j]=basis[idx+tmp]->Clone();
                idx+=bases[j];
            }
            // cout << endl;
            result[0]=Product(multVec);
            result[0]=cc->EvalMult(result[0],mask);
            //Cleanse
            result[0]=RotSum(result[0], size ,1);
        }
        

        return result;
    }


    // HECount §3.2 — coded counting restricted to a subset of the domain.
    vector<Ciphertext<DCRTPoly>> CountPartial(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const vector<usint> list){
        vector<vector<usint>> indices = DimDecomp(exponent, exponentbound);
        vector<usint> currentindices= indices[indices.size()-1];
        

        usint multnum = currentindices.size();
        vector<usint> bases(multnum);
        usint bound = list.size();
        for(usint i=0; i<multnum;i++){
            bases[i]=pow(base, currentindices[i]);
            // bound*=bases[i];
        }
        cout << "list number: " << bound << ", Multiplication num: " << multnum << ", Count Indices: " << currentindices << endl;


        vector<Ciphertext<DCRTPoly>> multVec(multnum);
        vector<Ciphertext<DCRTPoly>> result(bound);

        for(usint i=0; i<bound; i++){
            usint val = list[i];
            usint idx = 0;
            // cout << "val: " << val;
            for(usint j=0; j<multnum;j++){
                usint tmp = val%bases[j];
                // cout << ", " << tmp;
                val/=bases[j];
                multVec[j]=basis[idx+tmp]->Clone();
                idx+=bases[j];
            }
            // cout << endl;
            result[i]=Product(multVec);
            //Cleanse
            result[i]=RotSum(result[i], size ,1);
        }
        return result;
    }



    // HECount §3.1 / Alg 1 — NaiveCount: baseline counting using one EIF per domain element.
    vector<Ciphertext<DCRTPoly>> NaiveCount(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size){
        const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
        vector<usint> rounds = ParamEEF(bound, cc->GetCryptoParameters()->GetPlaintextModulus());


        vector<Ciphertext<DCRTPoly>> result(bound);

        for(usint i=0; i< bound; i++){
            result[i] = EEF(ciphertext, bound,rounds,i);
            result[i] = RotSum(result[i], size ,1);
        }
    
        
        return result;
    }


    // HECount §3.1 — NaiveCount SIMD variant.
    vector<Ciphertext<DCRTPoly>> NaiveCountSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size){
        const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
        vector<usint> rounds = ParamEEF(bound, cc->GetCryptoParameters()->GetPlaintextModulus());
        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        usint num = batchSize/size;
        usint iteration = bound / num;

        vector<Ciphertext<DCRTPoly>> result(iteration);

        if(num==1){
            for(usint i=0; i< bound; i++){
                result[i] = EEF(ciphertext, bound,rounds,i);
                result[i] = RotSum(result[i], size ,1);
            }
        }else{
            for(usint i=0; i< iteration; i++){
                Plaintext checker = GenEEFCheckerInterval(i*num, size, cc);
                result[i] = EEFSIMD(ciphertext, bound,rounds,checker);
                result[i] = RotSum(result[i], size ,1);
            }
        }
        
        return result;
    }



    // HECount §3.1 — NaiveCount restricted to a subset of the domain.
    vector<Ciphertext<DCRTPoly>> NaiveCountPartial(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size, const vector<usint> list){
        const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
        vector<usint> rounds = ParamEEF(bound, cc->GetCryptoParameters()->GetPlaintextModulus());
        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        usint num = batchSize/size;
        usint iteration = bound / num;

        vector<Ciphertext<DCRTPoly>> result(iteration);

        if(num==1){
            for(usint i=0; i< list.size(); i++){
                result[i] = EEF(ciphertext, bound, rounds, list[i]);
                result[i] = RotSum(result[i], size ,1);
            }
        }else{
            for(usint i=0; i< iteration; i++){
                Plaintext checker = GenEEFCheckerPartialArray(i*num, size, cc, list);
                result[i] = EEFSIMD(ciphertext, bound, rounds, checker);
                result[i] = RotSum(result[i], size ,1);
            }
        }
        
        return result;
    }



    // HECount §4.2 / Eq. 3 — IDF: encrypted inverse-document-frequency computation.
    vector<Ciphertext<DCRTPoly>> IDF(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint bound, const usint size, const vector<usint> list){
        const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
        vector<usint> rounds = ParamZeroTest(size, cc->GetCryptoParameters()->GetPlaintextModulus());
        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        double num = (double)(batchSize/size); //number of document

        vector<Ciphertext<DCRTPoly>> result(ciphertext.size());

        
        for(usint i=0; i< ciphertext.size(); i++){
            //Getting DF
            result[i] = ZeroTest(ciphertext[i], size, rounds);
            result[i] = cc->EvalSub(result[i], 1);
            cc->EvalNegateInPlace(result[i]);
            result[i] = RotSum(result[i], batchSize, size);

            result[i] = cc->EvalMult(result[i], 1/num);
            cc->ModReduceInPlace(result[i]);
            result[i] = cc->EvalSub(result[i], 1);
            for(usint j=0;j<3;j++){
                result[i] = cc->EvalMult(result[i], result[i]);
                cc->ModReduceInPlace(result[i]);
            }
            result[i] = cc->EvalMult(result[i], log(num));
            cc->ModReduceInPlace(result[i]);
        }
        
        
        return result;
    }



    // HECount §4.3 — IDFMult: multiply encrypted TF by plaintext IDF to obtain TF-IDF (encrypted).
    vector<Ciphertext<DCRTPoly>> IDFMult(const vector<Ciphertext<DCRTPoly>> ciphertext, const int32_t size, const vector<Plaintext> idf) {
        
        const CryptoContext<DCRTPoly> cc = ciphertext[1]->GetCryptoContext();
        // uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        vector<Ciphertext<DCRTPoly>> result(ciphertext.size()-1);


        for(usint i=1;i<ciphertext.size();i++){

            result[i-1] = cc->EvalMult(ciphertext[i], idf[i-1]);
            cc->ModReduceInPlace(result[i-1]);
            // result[i-1] = RotSum(tmp, -batchSize, -size);
        }
        

        return result;
    }



    // HECount §4.3 — DistanceComparison: distance + sign step of the IR pipeline (Eq. 12 first half).
    vector<Ciphertext<DCRTPoly>> DistanceComparison(const vector<Ciphertext<DCRTPoly>> ciphertext, const int32_t size, const vector<Plaintext> tfidf){
        const CryptoContext<DCRTPoly> cc = ciphertext[0]->GetCryptoContext();
        // uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        Ciphertext<DCRTPoly> result;
        vector<Ciphertext<DCRTPoly>> results(3);

        for(usint i=0;i<ciphertext.size();i++){
            Ciphertext<DCRTPoly> tmp = cc->EvalSub(ciphertext[i], tfidf[i]);
            tmp = cc->EvalMult(tmp,tmp);
            cc->ModReduceInPlace(tmp);
            
            if(i==0){
                result = tmp->Clone();
            }else{
                result = cc->EvalAdd(tmp,result);
            }
        }
        results[0] = RotSum(result, size, 1);



        const double divisor = 256;
        const double threshold = 4;
        cout << "Threshold: " << threshold << endl;
        result = cc->EvalSub(results[0], threshold);
        result = cc->EvalMult(result, 1 / divisor);
        cc->ModReduceInPlace(result);

        results[1] = ESF(result, divisor, false);
        result = cc->EvalPoly(results[1], {1, -0.5, -0.5});
        results[2] = Cleanse(result);

        return results;
    }

    // HECount §4.3 / Eq. 12 — Retrieval: extract the top-ranked entry by masking
    // (stride-`size` slot kept), broadcasting via RotSum, then multiplying by
    // the corpus `text` plaintext.
    Ciphertext<DCRTPoly> Retrieval(const Ciphertext<DCRTPoly> ciphertext, const int32_t size, Plaintext text){
        const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();

        // Stride-`size` mask: keep slot[i*size] for each i, zero elsewhere.
        vector<double> maskmsg(batchSize, 0.0);
        for (usint i = 0; i < batchSize / size; i++) maskmsg[i * size] = 1.0;
        Plaintext mask = cc->MakeCKKSPackedPlaintext(maskmsg);

        Ciphertext<DCRTPoly> result = cc->EvalMult(ciphertext, mask);
        cc->ModReduceInPlace(result);
        result = RotSum(result, -size, -1);

        result = cc->EvalMult(result, text);
        cc->ModReduceInPlace(result);


        return result;
    }

    // HECount §4.3 — precompute the plaintext TF × IDF arrays for the IR pipeline.
    vector<Plaintext> PrecomputeTFIDF(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize, const vector<double> tf, const vector<double> idf){
        vector<Plaintext> result(vocabsize/size);

        for(usint i=0;i< vocabsize/size; i++){
            vector<double> slice(batchSize);
            for(usint d=0;d<batchSize/size;d++){
                for(usint j=0;j<size;j++){
                    slice[d*size+j]=tf[d*vocabsize+i*size+j]*idf[i*size+j];
                }
            }
            result[i] = cc->MakeCKKSPackedPlaintext(slice);
        }

        return result;

    }


    // Helper — load a precomputed plaintext text vector from disk for the IR benchmark.
    Plaintext LoadText(const CryptoContext<DCRTPoly> cc, const usint size, const double scale){
        vector<double> textraw = readtexts(size, "reviewtext_amazon.txt", scale);
        uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        vector<double> slice(batchSize);
        for(usint i=0; i<batchSize; i++){
            slice[i]=textraw[i];
        }
        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(slice);
        
        return ptxt;
    }

    // Helper — load precomputed plaintext TF-IDF arrays from disk.
    vector<Plaintext> LoadTFIDF(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize){
        vector<double> texttfidf = readtexts(vocabsize, "tfidf_amazon.txt", 1, 0);
        vector<double> slice(batchSize);
        vector<Plaintext> result(vocabsize/size);
        for(usint i=0; i<vocabsize/size;i++){
            for(usint j=0; j<size;j++){
                for(usint k=0;k<batchSize/size;k++){
                    slice[k*size+j]=texttfidf[i*size+j+k*vocabsize];
                }
            }
            result[i] = cc->MakeCKKSPackedPlaintext(slice);
        }
        
        
        return result;
    }

    // Helper — load precomputed plaintext IDF arrays from disk.
    vector<Plaintext> LoadIDF(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize, const bool copy, const usint padidx){
        vector<double> textidf = readtexts(vocabsize, "idf_amazon.txt", 1, 0);
        vector<double> slice(batchSize);
        vector<Plaintext> result(vocabsize/size);
        usint kbound=1;
        if(copy)kbound=batchSize/size;
        for(usint i=0; i<vocabsize/size;i++){
            for(usint j=0; j<size;j++){
                for(usint k=0;k<kbound;k++){
                    slice[k*size+j]=textidf[i*size+j];
                }
            }
            if(padidx/size==i){
                slice[i*size+(padidx%size)]=0;
                // cout << padidx << " th entry is zero"<< endl;
            }
            result[i] = cc->MakeCKKSPackedPlaintext(slice);
        }
        
        
        return result;
    }


    // Helper — load a query token-index vector for the IR benchmark.
    vector<Plaintext> LoadQuery(const CryptoContext<DCRTPoly> cc, const usint base, const usint dim, const usint size, const usint batchSize, const usint idx){
        vector<double> samples = readtexts(size, "samples_amazon.txt");
        vector<usint> sampleint(size);
        vector<double> slice(batchSize);
        vector<Plaintext> result(dim);
        for(usint i=0; i<size;i++){
            sampleint[i]=(usint)(samples[idx*size+i]);
        }

        for(usint d=0; d<dim;d++){
            for(usint i=0; i<size;i++){
                slice[i]=(double)(sampleint[i]%base);
                sampleint[i]/=base;
            }
            result[d]=cc->MakeCKKSPackedPlaintext(slice);
        }

        
        return result;
    }


    // Helper — load a query TF (term-frequency) vector.
    vector<Plaintext> LoadQueryTF(const CryptoContext<DCRTPoly> cc, const usint packlen, const usint maxlen, const usint numvocab, const usint batchSize, const usint idx){
        vector<double> samples = readtexts(maxlen, "samples_amazon.txt");
        vector<usint> countvocab(numvocab);
        vector<usint> sent(maxlen);
        vector<double> slice(batchSize);
        for(usint i=0; i<maxlen;i++){
            countvocab[(usint)(samples[idx*maxlen+i])]+=1;
        }
        usint dim = numvocab/packlen;
        vector<Plaintext> result(dim);
        for(usint d=0; d<dim;d++){
            for(usint i=0; i<packlen;i++){
                slice[i]=(double)countvocab[i+d*packlen];
            }
            result[d]=cc->MakeCKKSPackedPlaintext(slice);
        }

        
        return result;
    }



    //----------------------------------------------------------------------------------
    // GenIndicatorCheckerForSIMDCOUNT — generator for the parallel-count indicator-checker
    // plaintexts used by CodedCountSIMD / ParalCount (HECount Alg 7).
    // Moved here from core/src/eif.cpp because it is hecount-specific.
    //----------------------------------------------------------------------------------

    // HECount §3.4 — indicator-checker plaintext generator for the SIMD-parallel counting basis.
vector<Plaintext> GenIndicatorCheckerForSIMDCOUNT(const usint base, const usint size, const usint paral,const CryptoContext<DCRTPoly> cc){
    int32_t batchSize = cc->GetEncodingParams()->GetBatchSize();

    std::vector<double> num(base);
    for(usint i=0 ; i < base; i ++){
        num[i]=(double)i;
    }

    vector<Plaintext> ptxts(paral);

    for(usint i=0;i<paral;i++){
        usint pp=pow(base,i);
        std::vector<double> nums(pp*size*base);
        nums = repeat(num, pp*size*base, pp*size);

        std::vector<double> numss(batchSize);
        numss = fullCopy(nums, batchSize, pp*size*base);
        
        ptxts[i] = cc->MakeCKKSPackedPlaintext(numss);
    }

    return ptxts;
}



}
