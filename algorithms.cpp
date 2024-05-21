#include "openfhe.h"
#include "utils.h"
#include "embedding.h"
#include "algorithms.h"
#include <iostream>
#include <vector>
#include <cmath>
#include "math/chebyshev.h"

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

void AddRotKeyForEmb(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t mk){
    int32_t copy=mk;
    std::vector<int32_t> arr(log2(mk));
    for(long i = 0 ; i < log2(mk) ; i++){
        copy >>= 1;
        arr[i]=(copy);
    }
    cc->EvalRotateKeyGen(privateKey, arr);
}

Plaintext GenIndicatorChecker(const usint bound, const CryptoContext<DCRTPoly> cc){
    auto batchSize = cc->GetRingDimension(); 
    batchSize >>=1;
    std::vector<double> num(bound);
    for(usint i=0 ; i < bound; i ++){
        num[i]=i;
    }

    std::vector<double> nums(batchSize);
    nums = fullCopy(num, batchSize, bound);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(nums);
    return ptxt;
}

vector<usint> GenIndicatorRounds(const usint bound, const usint scaleModSize){
	vector<usint> rounds(2);
    const usint boundbits=log2(bound);
    rounds[0]=2+boundbits*2;
    if(boundbits > 4)rounds[0]-=1;
    if(boundbits > 6)rounds[0]-=1;

    rounds[1]=1;
	if(boundbits > 3)rounds[1]+=1;
    if(boundbits > 5)rounds[1]+=1;

	if(scaleModSize >= 40){
        rounds[0]+=1;
        if(boundbits<=4)rounds[0]-=1;
        if(boundbits==7)rounds[0]+=1;
	}
    if(scaleModSize >= 45){
        if(boundbits<=4)rounds[0]+=1;
        if(boundbits==7)rounds[0]+=1;
        if(boundbits==9)rounds[0]+=1;
        if(boundbits==7)rounds[1]-=1;
        if(boundbits==6)rounds[1]-=1;
        if(boundbits==9)rounds[1]-=1;

	}
    if(scaleModSize >= 50){
        if(boundbits>6)rounds[0]+=1;
        if(boundbits==9)rounds[0]-=1;
        if(boundbits==13)rounds[0]-=1;
        if(boundbits==4)rounds[1]-=1;
        if(boundbits>6)rounds[1]-=1;
        if(boundbits==7){rounds[0]-=2; rounds[1]+=1;}
        if(boundbits==9)rounds[1]+=1;
        if(boundbits>=12)rounds[1]+=1;
	}
    if(scaleModSize >= 59){
        if(boundbits>4)rounds[0]+=1;
        if(boundbits>4)rounds[1]-=1;
	}
    if(boundbits==1)rounds[0]=0;
    if(boundbits==1 && scaleModSize >= 40)rounds[0]=1;
    if(boundbits==1 && scaleModSize >= 59)rounds[1]+=1;


    return rounds;
}

Ciphertext<DCRTPoly> RotAndSum(const Ciphertext<DCRTPoly> ciphertext, const int32_t from, const int32_t to) {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    Ciphertext<DCRTPoly> tmp; 
	
    const auto cc = ciphertext->GetCryptoContext();

    const int32_t round = log2(from/to);
	int32_t rotnum=from;
	for(int32_t s=0 ; s < round ; s++){
		rotnum >>=1;
        tmp = cc->EvalRotate(result, rotnum);
        result= cc->EvalAdd(result, tmp);
	}

    return result;
}

Ciphertext<DCRTPoly> Cleanse(Ciphertext<DCRTPoly> ciphertext, const usint round) {
	const auto cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = ciphertext->Clone();

	for(usint i=0; i < round; i++){
        Ciphertext<DCRTPoly> power = cc->EvalSquare(result);
        cc->ModReduceInPlace(power);
        Ciphertext<DCRTPoly> power2 = cc->EvalAdd(power,power);

        //cc->LevelReduceInPlace(result, nullptr, 1);

        result = cc->EvalMult(result, power2);
        cc->ModReduceInPlace(result);

        cc->EvalAddInPlace(power,power2);
        //cc->LevelReduceInPlace(power, nullptr, 1);
        result = cc->EvalSub(power, result);
	}
    return result;
}

Ciphertext<DCRTPoly> Indicator(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const double numtocheck){
    const auto cc = ciphertext->GetCryptoContext();
    const double div =1 / (double) bound;

	
    Ciphertext<DCRTPoly> result = cc->EvalSub(ciphertext, numtocheck);
    if(bound!=1.0)cc->EvalMultInPlace(result, div);
    cc->ModReduceInPlace(result);    
    result = cc->EvalSquare(result);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, result);
    cc->EvalAddInPlace(result, -1);

	for(usint i=0; i<rounds[0]; i++){
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
	}
	for(usint i=0; i < rounds[1]; i++){
        Ciphertext<DCRTPoly> power = cc->EvalSquare(result);
        cc->ModReduceInPlace(power);
        Ciphertext<DCRTPoly> power2 = cc->EvalAdd(power,power);

        //cc->LevelReduceInPlace(result, nullptr, 1);

        result = cc->EvalMult(result, power2);
        cc->ModReduceInPlace(result);

        cc->EvalAddInPlace(power,power2);
        //cc->LevelReduceInPlace(power, nullptr, 1);
        result = cc->EvalSub(power, result);
	}

    return result;
}

Ciphertext<DCRTPoly> IndicatorBinary(const Ciphertext<DCRTPoly> ciphertext, const vector<usint> rounds){
    const auto cc = ciphertext->GetCryptoContext();

	
    Ciphertext<DCRTPoly> result = cc->EvalSquare(ciphertext);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, -1);
    cc->EvalNegateInPlace(result);
	for(usint i=0; i<rounds[0]; i++){
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
	}
	for(usint i=0; i < rounds[1]; i++){
        Ciphertext<DCRTPoly> power = cc->EvalSquare(result);
        cc->ModReduceInPlace(power);
        Ciphertext<DCRTPoly> power2 = cc->EvalAdd(power,power);

        //cc->LevelReduceInPlace(result, nullptr, 1);

        result = cc->EvalMult(result, power2);
        cc->ModReduceInPlace(result);

        cc->EvalAddInPlace(power,power2);
        //cc->LevelReduceInPlace(power, nullptr, 1);
        result = cc->EvalSub(power, result);
	}

    return result;
}

Ciphertext<DCRTPoly> IndicatorSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const Plaintext numtocheck){
    const auto cc = ciphertext->GetCryptoContext();

    const double div =1 / (double) bound;
	
    Ciphertext<DCRTPoly> result = cc->EvalSub(ciphertext, numtocheck);
    cc->EvalMultInPlace(result, div); // Division By shift??
    cc->ModReduceInPlace(result);    
    result = cc->EvalSquare(result);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, result);
    cc->EvalAddInPlace(result, -1);

	for(usint i=0; i<rounds[0]; i++){
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
	}
	for(usint i=0; i < rounds[1]; i++){
        Ciphertext<DCRTPoly> power = cc->EvalSquare(result);
        cc->ModReduceInPlace(power);
        Ciphertext<DCRTPoly> power2 = cc->EvalAdd(power,power);

        //cc->LevelReduceInPlace(result, nullptr, 1);

        result = cc->EvalMult(result, power2);
        cc->ModReduceInPlace(result);

        cc->EvalAddInPlace(power,power2);
        //cc->LevelReduceInPlace(power, nullptr, 1);
        result = cc->EvalSub(power, result);
	}

    return result;
}


vector<double> GetCoeff(const usint bound){
    vector<double> coeff(bound);

    for(usint i=0; i < bound; i++){
        coeff[i]=0;
	}
    coeff[0]=1;
    for(usint i=1; i < bound; i++){
        for(usint j=i; j!=0; j--){
            coeff[j]=coeff[j-1]-coeff[j]*((double)i/(double)bound);
            
        }
        coeff[0]*=(-(double)i/(double)bound);    
	}


    // for(usint i=1; i < bound; i++){
    //     coeff[i]/=coeff[0];
    // }
    // coeff[0]=1;
    return coeff;
}

Ciphertext<DCRTPoly> IndicatorByLagrange(Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<double> coeff) {
	const auto cc = ciphertext->GetCryptoContext();

    Ciphertext<DCRTPoly> result =cc->EvalMult(ciphertext, 1/(double)bound);
    cc->ModReduceInPlace(result);
    result = cc->EvalPoly(result, coeff);
    result =cc->EvalMult(result, 1/(double)coeff[0]);
    cc->ModReduceInPlace(result);
    result = Cleanse(result,1);

    return result;
}


//----------------------------------------------------------------------------------
//   LUT
//----------------------------------------------------------------------------------

Ciphertext<DCRTPoly> encryptForSIMD(const vector<double> vals, const usint bound, const PublicKey<DCRTPoly> publicKey, CryptoContext<DCRTPoly> cc){
    auto batchSize = (cc->GetRingDimension()) >> 1; 
	vector<double> copied = repeat(vals, batchSize, bound);

    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(copied);
    auto c1 = cc->Encrypt(publicKey, ptxt1);
    return c1;
}

vector<Ciphertext<DCRTPoly>> lookUpTableLT(const Ciphertext<DCRTPoly> ciphertext, const vector<double> table, const usint bound, const usint outputdimension){
    Ciphertext<DCRTPoly> tmp;
    Ciphertext<DCRTPoly> indresult;
    vector<Ciphertext<DCRTPoly>> result(outputdimension);
    const auto cc = ciphertext->GetCryptoContext();
    auto scalingfactor = cc->GetEncodingParams()->GetPlaintextModulus();

    vector<usint> rounds=GenIndicatorRounds(bound,scalingfactor);

    TimeVar t;
    double timeind=0.0;

    for(usint j=0; j< bound; j++){
        TIC(t);
        indresult = Indicator(ciphertext, bound, rounds, (double)j);
        timeind+=TOC(t);
        for(usint i=0; i < outputdimension; i++){
            usint base=i*bound;
            if(j==0){
                result[i] = cc->EvalMult(indresult, table[base]);
            }else{
                tmp = cc->EvalMult(indresult, table[base+j]);
                cc->EvalAddInPlace(result[i],tmp);
            }
        }
    }
    for(usint i=0; i < outputdimension; i++){
        cc->ModReduceInPlace(result[i]);
    }	

    cout << "Ind Time: " << timeind << endl;

	//cout<< "Lookup done: " << result[0]->GetLevel() << endl;
    return result;
}

vector<Ciphertext<DCRTPoly>> lookUpTableCI(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension){
    Ciphertext<DCRTPoly> tmp;
    Ciphertext<DCRTPoly> indresult;
    vector<Ciphertext<DCRTPoly>> basis(bound*numcode);
    vector<Ciphertext<DCRTPoly>> result(outputdimension);
    vector<usint> base(2);
    usint totalbound = bound*bound;
    const auto cc = ciphertexts[0]->GetCryptoContext();
    auto scalingfactor = cc->GetEncodingParams()->GetPlaintextModulus();

    vector<usint> rounds=GenIndicatorRounds(bound,scalingfactor);

    TimeVar t;
    TIC(t);
    for(usint i=0; i< numcode; i++){
        for(usint j=0; j< bound; j++){
	        basis[i*bound+j] = Indicator(ciphertexts[i], bound, rounds, (double)j);
        }
    }
	double timeind=TOC(t);
    cout << "Ind Time: " << timeind << endl;

    //Only for numcode=2
    for(usint j=0; j< totalbound; j++){
        base[0]=j%bound;
        base[1]=j/bound;
        indresult = cc->EvalMult(basis[base[0]],basis[base[1]+bound]);
        cc->ModReduceInPlace(indresult);

        for(usint i=0; i < outputdimension; i++){
            usint base=totalbound*i;
            if(j==0){
                result[i] = cc->EvalMult(indresult, table[base]);
            }else{
                tmp = cc->EvalMult(indresult, table[base+j]);
                cc->EvalAddInPlace(result[i],tmp);
            }
        }
    }
    for(usint i=0; i < outputdimension; i++){
        cc->ModReduceInPlace(result[i]);
    }	
	//cout<< "Lookup done: " << result[0]->GetLevel() << endl;
    return result;
}


vector<Ciphertext<DCRTPoly>> lookUpTable(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension) {
	Ciphertext<DCRTPoly> tmp;
    vector<Ciphertext<DCRTPoly>> basis(bound*numcode);
    vector<Ciphertext<DCRTPoly>> result(outputdimension);
    const auto cc = ciphertexts[0]->GetCryptoContext();
    auto scalingfactor = cc->GetEncodingParams()->GetPlaintextModulus();

    vector<usint> rounds=GenIndicatorRounds(bound,scalingfactor);

    TimeVar t;
    TIC(t);

    for(usint i=0; i< numcode; i++){
        for(usint j=0; j< bound; j++){
	        basis[i*bound+j] = Indicator(ciphertexts[i], bound, rounds, (double)j);
        }
    }
	
	double timeind=TOC(t);
    cout << "Ind Time: " << timeind << endl;

	for(usint i=0; i < outputdimension; i++){
		usint base=i*bound*numcode;
        result[i] = cc->EvalMult(basis[0], table[base]);
        for(usint j=1;j< bound*numcode; j++){
            tmp = cc->EvalMult(basis[j], table[base+j]);
            cc->EvalAddInPlace(result[i],tmp);
        }
        cc->ModReduceInPlace(result[i]);
	}
	//cout<< "Lookup done: " << result[0]->GetLevel() << endl;
    return result;
}

vector<Ciphertext<DCRTPoly>> lookUpTableSIMD(const Ciphertext<DCRTPoly> ciphertext, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension) {
	Ciphertext<DCRTPoly> tmp;
    vector<Ciphertext<DCRTPoly>> result;
    const auto cc = ciphertext->GetCryptoContext();
    auto batchSize = (cc->GetRingDimension()) >> 1; 
    auto scalingfactor = cc->GetEncodingParams()->GetPlaintextModulus();

	usint base;
	vector<double> subtable(bound*numcode);
	vector<double> fulltable(batchSize);

    TimeVar t;
    TIC(t);

    Plaintext numtocheck = GenIndicatorChecker(bound, cc);
    vector<usint> rounds=GenIndicatorRounds(bound,scalingfactor);
	Ciphertext<DCRTPoly> indresult = IndicatorSIMD(ciphertext, bound, rounds, numtocheck);
	
	double timeind=TOC(t);
    cout << "Ind Time: " << timeind << endl;

	for(usint i=0; i < outputdimension; i++){
		base=i*bound*numcode;
		for(usint j=0; j< bound*numcode; j++){
			subtable[j]=table[base+j];
		}
        fulltable = fullCopy(subtable, batchSize, bound*numcode);
        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(fulltable);
        tmp = cc->EvalMult(indresult, ptxt);
        cc->ModReduceInPlace(tmp);
        tmp =  RotAndSum(tmp, bound*numcode, 1);
        result.push_back(tmp);
	}
	//cout<< "Lookup done: " << result[0]->GetLevel() << endl;
    return result;
}

//----------------------------------------------------------------------------------
//   Comparison
//----------------------------------------------------------------------------------

Ciphertext<DCRTPoly> comparison(const Ciphertext<DCRTPoly> ciphertext, const usint degf, const usint degg, double bound, const usint ver){
    const auto cc = ciphertext->GetCryptoContext();
    auto result = ciphertext->Clone();

    std::vector<double> fcoeff;
    std::vector<double> gcoeff;

    if(ver==1){
        fcoeff= {0, 1.5, 0, -0.5};
        gcoeff= {0, 2.076171875, 0, -1.3271484375};        
    }

    if(ver==2){
        fcoeff = {0, 1.875, 0, -1.25, 0, 0.375};
        gcoeff = {0, 3.255859375, 0, -5.96484375, 0, 3.70703125};
    }

    if(ver==3){
        fcoeff = {0, 2.1875, 0, -2.1875, 0, 1.3125, 0, -0.3125};
        gcoeff = {0, 4.4814453125, 0, -16.1884765625, 0, 25.013671875, 0, -12.55859375};
    }

    if(ver==4){
        fcoeff= {0, 2.4609375, 0, -3.28125, 0, 2.953125, 0, -1.40625, 0 , 0.2734375};
        gcoeff= {0, 5.712890625, 0, -34.154296875, 0, 94.7412109375, 0, -110.83203125, 0 , 45.5302734375};
    }
    for(usint i=0;i<degg;i++){
        vector<Ciphertext<DCRTPoly>> powers(3);
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
    for(usint i=0;i<degf;i++){
        vector<Ciphertext<DCRTPoly>> powers(3);
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

        result=cc->EvalMult(result, 2.1875);
        powers[0]=cc->EvalMult(powers[0], -2.1875);
        powers[1]=cc->EvalMult(powers[1], 1.3125);
        powers[2]=cc->EvalMult(powers[2], -0.3125);
        result = cc-> EvalAdd(result,powers[0]);
        result = cc-> EvalAdd(result,powers[1]);
        result = cc-> EvalAdd(result,powers[2]);
        cc->ModReduceInPlace(result);    
    }
    return result;
}

Ciphertext<DCRTPoly> comp(const Ciphertext<DCRTPoly> ciphertext, const double bound, const bool boot,  const bool lastmod){
    const auto cc = ciphertext->GetCryptoContext();
    auto result = ciphertext->Clone();
    
    usint degg=2;
    auto logbound=log2(bound);
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

        if(i==degf-1 && lastmod == true){
            result=cc->EvalMult(result, 1.09375);
            powers[0]=cc->EvalMult(powers[0], -1.09375);
            powers[1]=cc->EvalMult(powers[1], 0.65625);
            powers[2]=cc->EvalMult(powers[2], -0.15625);
            result = cc-> EvalAdd(result,powers[0]);
            result = cc-> EvalAdd(result,powers[1]);
            result = cc-> EvalAdd(result,powers[2]);
            cc->ModReduceInPlace(result);
            result = cc-> EvalAdd(result, 0.5);
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


Ciphertext<DCRTPoly> discreteEqualZero(const Ciphertext<DCRTPoly> ciphertext, const usint d, const usint K){
    const auto cc = ciphertext->GetCryptoContext();
    double bound = (double)(1 << d);
    const double PI = 3.1415926;
    double div = 1/bound;
    Ciphertext<DCRTPoly> norm = cc->EvalMult(ciphertext, div); 
    cc->ModReduceInPlace(norm);
    Ciphertext<DCRTPoly> coscipher = cc->EvalChebyshevFunction([PI](double x) -> double { return std::cos(x*PI);}, norm,-1 , 1, K);
    Ciphertext<DCRTPoly> sinccipher = cc->EvalChebyshevFunction([PI](double x) -> double { if(x!=0){return std::sin(PI*x)/(PI*x);}else{return 1;} }, norm,-1 , 1, K);

    sinccipher = cc->EvalMult(sinccipher, coscipher);
    for(usint i=1; i<d;i++){
        cc-> ModReduceInPlace(sinccipher);

        coscipher = cc->EvalMult(coscipher,coscipher);
        cc-> ModReduceInPlace(coscipher);
        coscipher = cc->EvalAdd(coscipher,coscipher);
        coscipher = cc->EvalSub(coscipher,1);
        sinccipher = cc->EvalMult(sinccipher, coscipher);
    }
    cc-> ModReduceInPlace(sinccipher);
    //return sinccipher;

    sinccipher = cc->EvalPoly(sinccipher, {0,0,4,-3});
    return sinccipher;
}


}