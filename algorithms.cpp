#include "openfhe.h"
#include "utils.h"
#include "embedding.h"
#include "algorithms.h"
#include <iostream>
#include <vector>
#include <cmath>
// #include "openfhecore.h"
// #include "math/chebyshev.h"
#include <map>

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

Ciphertext<DCRTPoly> Product(const vector<Ciphertext<DCRTPoly>> ciphertext){
    usint num = ciphertext.size();
    usint phase = ceil(log2(num));
    usint res = 0;
    const auto cc = ciphertext[0]->GetCryptoContext();

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

Ciphertext<DCRTPoly> RotSlow(const Ciphertext<DCRTPoly> ciphertext, const int32_t i, const usint size){
    const auto cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> tmp=ciphertext->Clone();
    int32_t num=i;
    if(i < 0){
        return RotSlowMinus(ciphertext, -i, size);
    }

    int32_t rotnum = 1;
    for(usint j=0; j<log2(size);j++){
        if(num%2==1){
            tmp = cc->EvalRotate(tmp, rotnum);
        }
        num >>=1;
        rotnum*=2;

    }
    return tmp;


}

Ciphertext<DCRTPoly> RotSlowMinus(const Ciphertext<DCRTPoly> ciphertext, const int32_t i, const usint size){
    const auto cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> tmp=ciphertext->Clone();
    int32_t num=i;
    
    if(i < 0){
        return RotSlow(ciphertext, -i, size);
    }

    int32_t rotnum = 1;
    for(usint j=0; j<log2(size);j++){
        if(num%2==1){
            tmp = cc->EvalRotate(tmp, -rotnum);
        }
        num >>=1;
        rotnum*=2;

    }
    return tmp;


}

Ciphertext<DCRTPoly> EvalLog(const Ciphertext<DCRTPoly> ciphertext, const double bound, const double base, const usint degree){
    const auto cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = cc->EvalMult(ciphertext, 1/bound);
    cc->ModReduceInPlace(result);
    result = cc->EvalSub(result, 1); // y = x/bound -1

    vector<double> coeff(degree+1);
    double logbase = 1;
    if(base>1)logbase = log(base);
    double coeff0 = 1/logbase;
    coeff[0]=0;
    for(usint i=1; i<degree+1; i++){
        coeff[i]=coeff0/(double)i;
        coeff0=-coeff0;
    }
    //log (1+y) +log(bound) = log x
    result = cc->EvalPoly(result, coeff);

    // Ciphertext<DCRTPoly> pert = EvalInverseAuto(ciphertext, bound);
    // pert = cc->EvalSub(pert, 1);
    // for(usint i=0; i< log2(degree); i++){
    //     cc->EvalMultInPlace(pert,pert);
    //     cc->ModReduceInPlace(pert);
    // }
    // cc->EvalMultInPlace(pert,log(bound)/logbase);
    // cc->ModReduceInPlace(pert);


    // result = cc->EvalAdd(result, log(bound)/logbase);
    // result = cc->EvalAdd(result, pert);

    return result;
}


Ciphertext<DCRTPoly> EvalLogLike(const Ciphertext<DCRTPoly> ciphertext, const double bound){
    const auto cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> result = cc->EvalMult(ciphertext, 1/bound);
    cc->ModReduceInPlace(result);

    vector<double> coeff={0, 1, -0.5};
    result = cc->EvalPoly(result, coeff);

    return result;
}


Ciphertext<DCRTPoly> EvalInverse(const Ciphertext<DCRTPoly> ciphertext, const double bound, const usint degree){
    const auto cc = ciphertext->GetCryptoContext();
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


Plaintext GenIndicatorChecker(const usint bound, const CryptoContext<DCRTPoly> cc){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    std::vector<double> num(bound);
    for(usint i=0 ; i < bound; i ++){
        num[i]=i;
    }

    std::vector<double> nums(batchSize);
    nums = fullCopy(num, batchSize, bound);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(nums);
    return ptxt;
}

Plaintext GenIndicatorCheckerInterval(const usint from, const usint size, const CryptoContext<DCRTPoly> cc){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();

    std::vector<double> num(batchSize/size);
    for(usint i=0 ; i < batchSize/size; i ++){
        num[i]=from+i;
    }

    std::vector<double> nums(batchSize);
    nums = repeat(num, batchSize, size);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(nums);
    return ptxt;
}


Plaintext GenIndicatorCheckerIntervalRecursive(const usint from, const usint to, const usint size, const CryptoContext<DCRTPoly> cc){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();

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

Plaintext GenIndicatorCheckerForSort(const usint size, const CryptoContext<DCRTPoly> cc, const usint iter){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    auto sizesquare = size*size;
    auto numct = sizesquare / batchSize;
    if(numct != 0){
        auto slicelength = size / numct;

        std::vector<double> num(slicelength);
        for(usint i=0 ; i < slicelength; i ++){
            num[i]=(double)(iter*slicelength+i);
        }
        std::vector<double> nums(batchSize);
        nums = repeat(nums, batchSize, size);
        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(nums);
        return ptxt;
    }else{
        std::vector<double> num(batchSize / size);
        for(usint i=0 ; i < batchSize / size; i ++){
            num[i]=(double)(i % size);
        }

        std::vector<double> nums(batchSize);
        nums = repeat(num, batchSize, size);

        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(nums);
        return ptxt;
    }
    
}


vector<Plaintext> GenIndicatorCheckerForSIMDCOUNT(const usint base, const usint size, const usint paral,const CryptoContext<DCRTPoly> cc){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();

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


Plaintext GenIndicatorCheckerPartialArray(const usint from, const usint size, const CryptoContext<DCRTPoly> cc, const vector<usint> list){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();

    std::vector<double> num(batchSize/size);
    for(usint i=0 ; i < batchSize/size; i ++){
        num[i]=list[from+i];
    }

    std::vector<double> nums(batchSize);
    nums = repeat(num, batchSize, size);
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
    // if(boundbits==1 && scaleModSize >= 40)rounds[0]=1;
    if(boundbits==1 && scaleModSize >= 59)rounds[1]+=1;


    return rounds;
}


vector<usint> GenZeroTestRounds(const usint bound, const usint scaleModSize){
	vector<usint> rounds(2);
    const usint boundbits=log2(bound);
    rounds[0]=2+boundbits;

    rounds[1]=1;
	if(boundbits > 3)rounds[1]+=1;

	if(scaleModSize >= 40){
        rounds[0]+=1;
        if(boundbits==4)rounds[1]-=1;
        if(boundbits==5)rounds[1]-=1;
	}
    if(scaleModSize >= 45){
        if(boundbits==6)rounds[1]-=1;
        if(boundbits==7)rounds[1]-=1;
	}
    if(scaleModSize >= 50){
        if(boundbits>2)rounds[0]+=1;
        if(boundbits>6)rounds[0]-=1;

        if(boundbits==8)rounds[1]-=1;
        if(boundbits==9)rounds[1]-=1;
        if(boundbits==10)rounds[1]-=1;

	}
    if(scaleModSize >= 59){
        if(boundbits==2)rounds[0]+=1;
        if(boundbits>6)rounds[0]+=1;

        if(boundbits>10)rounds[1]-=1;
	}
    if(boundbits==1)rounds[0]=0;
    if(boundbits==1)rounds[1]=0;

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


    Ciphertext<DCRTPoly> result;
    if(bound > 2){
        result = cc->EvalSub(ciphertext, numtocheck);
        cc->EvalMultInPlace(result, div);
        cc->ModReduceInPlace(result);    
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
        cc->EvalAddInPlace(result, result);
        cc->EvalAddInPlace(result, -1);
    }
    if(bound == 2 && numtocheck==1)result = ciphertext->Clone();
    if(bound == 2 && numtocheck==0){
        result = cc->EvalAdd(ciphertext, -1);
        cc->EvalNegateInPlace(result);
    }

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


Ciphertext<DCRTPoly> ZeroTest(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds){
    const auto cc = ciphertext->GetCryptoContext();
    const double div =1 / (double) bound;

	
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    if(bound!=1.0){
        result = cc->EvalMult(result, div);
        cc->ModReduceInPlace(result);
    }
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

Ciphertext<DCRTPoly> IndicatorSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const Plaintext numtocheck){
    const auto cc = ciphertext->GetCryptoContext();

    const double div =1 / (double) bound;
	
    Ciphertext<DCRTPoly> result;
    
    if(bound > 2){
        result = cc->EvalSub(ciphertext, numtocheck);
        cc->EvalMultInPlace(result, div); 
        cc->ModReduceInPlace(result);    
        result = cc->EvalSquare(result);
        cc->ModReduceInPlace(result);
        cc->EvalAddInPlace(result, result);
        cc->EvalAddInPlace(result, -1);
    }

    if(bound == 2){
        vector<double> checker = numtocheck->GetRealPackedValue();
        vector<double> checkeradd(checker.size());
        vector<double> checkermult(checker.size());
        for(usint i=0; i<checker.size(); i++){
            if(checker[i]>0.5){
                checkeradd[i]=0.0;
                checkermult[i]=1.0;
            }else{
                checkeradd[i]=1.0;
                checkermult[i]=-1.0;
            }
        }
        Plaintext ptxtadd = cc->MakeCKKSPackedPlaintext(checkeradd);
        Plaintext ptxtmult = cc->MakeCKKSPackedPlaintext(checkermult);
        result = cc->EvalMult(ciphertext, ptxtmult);
        result = cc->EvalAdd(result, ptxtadd);
        // cc->EvalNegateInPlace(result);
    }

    //     result = cc->EvalSquare(result);
    //     cc->ModReduceInPlace(result);
    //     cc->EvalAddInPlace(result, -1);
    //     cc->EvalNegateInPlace(result);
    // }

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
//   Logistic Regression
//----------------------------------------------------------------------------------

Ciphertext<DCRTPoly> encrypt_sentence_SIMD(const CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly> publicKey, const vector<string> sentence, CompressedEmbedding model){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    usint mk = model.m * model.k ;
    vector<usint> idx(model.m);
    std::vector<double> restmp(batchSize / model.k);
    for(usint i=0; i< batchSize / mk ; i++){
        if ( model.wordtoindex.find(sentence[i]) == model.wordtoindex.end() ) {
            for(usint j=0; j<model.m; j++){
                idx[j]=model.k;
            }
        } else {
            idx = model.wordtoindex[sentence[i]];
        }
        for(usint j=0; j<model.m; j++){
            restmp[i*model.m+j]=(double)idx[j];
        }
    }
    std::vector<double> result(batchSize);
    result = repeat(restmp, batchSize, model.k);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(result);
    auto c1 = cc->Encrypt(publicKey, ptxt);

    return c1;
}


Ciphertext<DCRTPoly> inference_encrypted_SIMD(const vector<Ciphertext<DCRTPoly>> emb, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg) {
    const auto cc = emb[0]->GetCryptoContext();
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    const usint mkl = model.m*model.k*length;
    const usint mk = model.m*model.k;
    const usint numsent = batchSize / mkl;

    // auto emb = lookUpTableSIMD(ciphertexts, model.weight, model.k, model.m, model.outputdimension);


    std::vector<double> weights(batchSize);
    for(usint j=0; j<numsent; j++){
        for(usint k=0; k<length; k++){
            weights[j*mkl+mk*k] = logreg.weight[0] / lengthvec[j];
        }
    }
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(weights);
    auto res = cc->EvalMult(emb[0], ptxt);

    for(usint i = 0; i< model.outputdimension ; i++){
        for(usint j=0; j<numsent; j++){
            for(usint k=0; k<length; k++){
                weights[j*mkl+mk*k] = logreg.weight[i] / lengthvec[j];
            }
        }
        ptxt = cc->MakeCKKSPackedPlaintext(weights);
        auto tmp = cc->EvalMult(emb[i], ptxt);
        res = cc->EvalAdd(res, tmp);
    }
    res =  RotAndSum(res, mkl, mk);
    res = cc->EvalAdd(res, logreg.weight[model.outputdimension]);
    cc->ModReduceInPlace(res);    

    double upperbd = 64;

    res = cc->EvalLogistic(res, -upperbd, upperbd, 128);

    return res;

}


vector<Ciphertext<DCRTPoly>> encrypt_sentence(const CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly> publicKey, const vector<string> sentence, CompressedEmbedding model){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    vector<Ciphertext<DCRTPoly>> result(model.m);

    std::vector<double> restmp(batchSize);
    for(usint j=0; j< model.m; j++){
        for(usint i=0; i< batchSize; i++){
            if ( model.wordtoindex.find(sentence[i]) == model.wordtoindex.end()) {
                restmp[i] = (double) model.k;
                
            } else {
                restmp[i] = (double) model.wordtoindex[sentence[i]][j];
            }
        }
        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(restmp);
        result[j] = cc->Encrypt(publicKey, ptxt);

    }

    
    return result;
}


Ciphertext<DCRTPoly> inference_encrypted(const vector<Ciphertext<DCRTPoly>> emb, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg) {
    const auto cc = emb[0]->GetCryptoContext();
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    // const usint mkl = model.m*model.k*length;
    // const usint mk = model.m*model.k;
    const usint numsent = batchSize / length;

    // auto emb = lookUpTableSIMD(ciphertexts, model.weight, model.k, model.m, model.outputdimension);
    

    std::vector<double> weights(batchSize);
    for(usint j=0; j<numsent; j++){
        for(usint k=0; k<length; k++){
            weights[j*length+k] = logreg.weight[0] / lengthvec[j];
        }
    }
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(weights);
    auto res = cc->EvalMult(emb[0], ptxt);

    for(usint i = 1; i< model.outputdimension ; i++){
        for(usint j=0; j<numsent; j++){
            for(usint k=0; k<length; k++){
                weights[j*length+k] = logreg.weight[i] / lengthvec[j];
            }
        }
        ptxt = cc->MakeCKKSPackedPlaintext(weights);
        auto tmp = cc->EvalMult(emb[i], ptxt);
        res = cc->EvalAdd(res, tmp);
    }
    res =  RotAndSum(res, length, 1);
    res = cc->EvalAdd(res, logreg.weight[model.outputdimension]);
    // cc->ModReduceInPlace(res);

    // double upperbd = 64;

    // res = cc->EvalLogistic(res, -upperbd, upperbd, 128);

    return res;

}

vector<vector<double>> sentencembedding_plain(const CryptoContext<DCRTPoly> cc, const vector<string> sentence, CompressedEmbedding model){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    vector<vector<double>> result;
    // usint mk = model.m * model.k;

    // for(usint j=0; j< model.m; j++){
    //     std::vector<double> restmp(batchSize);
    //     for(usint i=0; i< batchSize; i++){
    //         if ( model.wordtoindex.find(sentence[i]) == model.wordtoindex.end()) {
    //             restmp[i] = model.k;
                
    //         } else {
    //             restmp[i] = model.wordtoindex[sentence[i]][j];
    //         }
    //     }        
    //     emb.push_back(restmp);
    // }

    vector<double> table = model.weight;
    for(usint i=0; i< model.outputdimension; i++){
        usint base = i * model.m * model.k;
        std::vector<double> restmp(batchSize);
            
        for(usint k=0; k< batchSize; k++){
            if ( model.wordtoindex.find(sentence[k]) == model.wordtoindex.end()) {
                    restmp[k] = 0.0;        
            } else {
                for(usint j=0; j< model.m; j++){
                    // if(k==512 && i==0)cout << model.wordtoindex[sentence[k]][j] << "," << table[base+ j*model.k + model.wordtoindex[sentence[k]][j]] << ", " << restmp[k] << endl;
                    restmp[k] += table[base+ j*model.k + model.wordtoindex[sentence[k]][j]];

                }
            }
        }
        result.push_back(restmp);
    }

    return result;
}

vector<double> inference_plain(const CryptoContext<DCRTPoly> cc, vector<vector<double>> emb, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg){
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    // const usint mkl = model.m*model.k*length;
    // const usint mk = model.m*model.k;
    const usint numsent = batchSize / length;

    // auto emb = lookUpTableSIMD(ciphertexts, model.weight, model.k, model.m, model.outputdimension);
    

    std::vector<double> result(numsent);
    for(usint j=0; j<numsent; j++){
        for(usint k=0; k<length; k++){
            for(usint i=0; i<model.outputdimension; i++){
                result[j] += emb[i][j*length+k]*logreg.weight[i];
            }
        }
        result[j] /= lengthvec[j];
        result[j] += logreg.weight[model.outputdimension];

        // result[j] = 1/(1+exp(-result[j]));
    }
    
    return result;


}


//----------------------------------------------------------------------------------
//   Comparison
//----------------------------------------------------------------------------------

Ciphertext<DCRTPoly> normalize(const Ciphertext<DCRTPoly> ciphertext, double bound){
    const auto cc = ciphertext->GetCryptoContext();
    
    const double div =1 / (double) bound;
    auto result = cc->EvalMult(ciphertext, div);
    cc->ModReduceInPlace(result);    
    
    return result;
}

// Ciphertext<DCRTPoly> comparison(const Ciphertext<DCRTPoly> ciphertext, const usint degf, const usint degg, double bound, const usint ver){
//     const auto cc = ciphertext->GetCryptoContext();
//     auto result = ciphertext->Clone();

//     std::vector<double> fcoeff;
//     std::vector<double> gcoeff;

//     if(ver==1){
//         fcoeff= {0, 1.5, 0, -0.5};
//         gcoeff= {0, 2.076171875, 0, -1.3271484375};        
//     }

//     if(ver==2){
//         fcoeff = {0, 1.875, 0, -1.25, 0, 0.375};
//         gcoeff = {0, 3.255859375, 0, -5.96484375, 0, 3.70703125};
//     }

//     if(ver==3){
//         fcoeff = {0, 2.1875, 0, -2.1875, 0, 1.3125, 0, -0.3125};
//         gcoeff = {0, 4.4814453125, 0, -16.1884765625, 0, 25.013671875, 0, -12.55859375};
//     }

//     if(ver==4){
//         fcoeff= {0, 2.4609375, 0, -3.28125, 0, 2.953125, 0, -1.40625, 0 , 0.2734375};
//         gcoeff= {0, 5.712890625, 0, -34.154296875, 0, 94.7412109375, 0, -110.83203125, 0 , 45.5302734375};
//     }
//     for(usint i=0;i<degg;i++){
//         result = cc->EvalPoly(result, gcoeff);
//     }
//     for(usint i=0;i<degf;i++){
//         result = cc->EvalPoly(result, fcoeff);
//     }
//     return result;
// }

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
    // if(logbound>5)degg+=1;
    // if(logbound>7)degg+=1;
    // if(logbound>9)degg+=1;
    if(logbound>3)degg=logbound/2;



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


vector<vector<usint>> GenIndices(const usint exponent, const usint exponentbound, const bool maximalmode){
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


vector<Ciphertext<DCRTPoly>> MakeBasisBlock(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint level, vector<vector<usint>> indices, const bool maximalmode){
    const auto cc = ciphertext[0]->GetCryptoContext();
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




vector<Ciphertext<DCRTPoly>> MakeBasis(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint exponentbound, const bool maximalmode){
    usint exponent = ciphertext.size()/base;
    vector<vector<usint>> indices = GenIndices(exponent, exponentbound, maximalmode);
    // usint res=0;
    // for(usint i=0; i<indices[indices.size()-1].size(); i++){
    //     res+=pow(base, indices[indices.size()-1][i]);
    // }
    // cout << "Result Cipher num: " << res << endl;

    vector<Ciphertext<DCRTPoly>> tmp;
    // cout << "Start: " << ciphertext.size() <<endl;

    if(exponentbound==1 || indices.size()==1){
        return ciphertext;
    }else{
        tmp = MakeBasisBlock(ciphertext, base, 1, indices, maximalmode);
        // cout << "Step 0: " << tmp.size() << " ciphertexts, " << indices[1] <<endl;
    }

    for(usint i=1;i<indices.size()-1;i++){
        tmp = MakeBasisBlock(tmp, base, i+1, indices, maximalmode);
        // cout << "Step " << i << ": " << tmp.size() <<  " ciphertexts, " << indices[i+1] <<endl;

    }
    
    return tmp;
}




vector<Ciphertext<DCRTPoly>> ToOHESIMD(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size){
    const auto cc = ciphertext[0]->GetCryptoContext();
    usint num = ciphertext.size();
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
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
    auto rounds = GenIndicatorRounds(base, cc->GetCryptoParameters()->GetPlaintextModulus());

    for(usint i=0;i< num ; i++){
        result[i]=IndicatorSIMD(ciphertext[i], base, rounds, ptxts[i%paral]);
        
    }
    return result;
}


vector<Ciphertext<DCRTPoly>> MakeBasisBlockSIMD(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size, const usint paral, const usint leftover, const usint level, vector<vector<usint>> indices, const bool maximalmode){
    const auto cc = ciphertext[0]->GetCryptoContext();
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


vector<Ciphertext<DCRTPoly>> MakeBasisSIMD(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size, const usint exponentbound, const bool maximalmode){
    usint exponent = ciphertext.size();
    const auto cc = ciphertext[0]->GetCryptoContext();
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();

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


    vector<vector<usint>> indicestmp = GenIndices(newexponent, exponentbound, maximalmode);
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
        tmp = MakeBasisBlockSIMD(fullbasis, base, size, paral, leftover, 1, indices, maximalmode);
        // cout << "Step 0: " << tmp.size() << " ciphertexts, " << indices[1] <<endl;
    }

    for(usint i=1;i<indices.size()-1;i++){
        tmp = MakeBasisBlockSIMD(tmp, base, size, paral, leftover, i+1, indices, maximalmode);
        // cout << "Step " << i << ": " << tmp.size() <<  " ciphertexts, " << indices[i+1] <<endl;
    }
    
    return tmp;
}




vector<Ciphertext<DCRTPoly>> ToOHE(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base){
    const auto cc = ciphertext[0]->GetCryptoContext();
    usint num = ciphertext.size();
    vector<Ciphertext<DCRTPoly>> result(base*num);
    auto rounds = GenIndicatorRounds(base, cc->GetCryptoParameters()->GetPlaintextModulus());

    for(usint i=0;i< num ; i++){
        for(usint j=0; j<base; j++){
            result[base*i+j]=Indicator(ciphertext[i],base, rounds, j);
        }    
    }
    return result;
}



	
vector<Ciphertext<DCRTPoly>> Count(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const usint gather){
    const auto cc = basis[0]->GetCryptoContext();
    vector<vector<usint>> indices = GenIndices(exponent, exponentbound);
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
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
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
        result[i*ridx]=RotAndSum(result[i*ridx], size ,1);

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

vector<Ciphertext<DCRTPoly>> CountSIMD(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint rotsumsize, const usint exponent){
    const auto cc = basis[0]->GetCryptoContext();
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();


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
    vector<vector<usint>> indices = GenIndices(newexponent, 0, false);
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
            resulttmp[i]=RotAndSum(basis[i], rotsumsize ,1);
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
                tmp[0]=RotAndSum(tmp[0], rotsumsize ,1);
                // cout << "gen " << j*powedindices[1]*rotidx+k*rotidx+l << endl;
                result[j*powedindices[1]*rotidx+k*rotidx+l]=tmp[0]->Clone();
            }
        }
    }    

    return result;
}


vector<Ciphertext<DCRTPoly>> NgramBasis(const vector<Ciphertext<DCRTPoly>> basis, const usint n){
    usint basissize=basis.size();
    vector<Ciphertext<DCRTPoly>> result(n*basissize);
    const auto cc = basis[0]->GetCryptoContext();


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


vector<Ciphertext<DCRTPoly>> Ngram(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const usint n, const double ratio, const bool maximalmode){
    const auto cc = basis[0]->GetCryptoContext();
    vector<vector<usint>> indices = GenIndices(exponent, exponentbound, maximalmode);
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


    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
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
        result[0]=RotAndSum(result[0], size ,1);
    }
    

    return result;
}


vector<Ciphertext<DCRTPoly>> CountPartial(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const vector<usint> list){
    vector<vector<usint>> indices = GenIndices(exponent, exponentbound);
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
        result[i]=RotAndSum(result[i], size ,1);
    }
    return result;
}



vector<Ciphertext<DCRTPoly>> NaiveCount(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size){
    const auto cc = ciphertext->GetCryptoContext();
    auto rounds = GenIndicatorRounds(bound, cc->GetCryptoParameters()->GetPlaintextModulus());


    vector<Ciphertext<DCRTPoly>> result(bound);

    for(usint i=0; i< bound; i++){
        result[i] = Indicator(ciphertext, bound,rounds,i);
        result[i] = RotAndSum(result[i], size ,1);
    }
   
    
    return result;
}


vector<Ciphertext<DCRTPoly>> NaiveCountSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size){
    const auto cc = ciphertext->GetCryptoContext();
    auto rounds = GenIndicatorRounds(bound, cc->GetCryptoParameters()->GetPlaintextModulus());
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    usint num = batchSize/size;
    usint iteration = bound / num;

    vector<Ciphertext<DCRTPoly>> result(iteration);

    if(num==1){
        for(usint i=0; i< bound; i++){
            result[i] = Indicator(ciphertext, bound,rounds,i);
            result[i] = RotAndSum(result[i], size ,1);
        }
    }else{
        for(usint i=0; i< iteration; i++){
            Plaintext checker = GenIndicatorCheckerInterval(i*num, size, cc);
            result[i] = IndicatorSIMD(ciphertext, bound,rounds,checker);
            result[i] = RotAndSum(result[i], size ,1);
        }
    }
    
    return result;
}



vector<Ciphertext<DCRTPoly>> NaiveCountPartial(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size, const vector<usint> list){
    const auto cc = ciphertext->GetCryptoContext();
    auto rounds = GenIndicatorRounds(bound, cc->GetCryptoParameters()->GetPlaintextModulus());
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    usint num = batchSize/size;
    usint iteration = bound / num;

    vector<Ciphertext<DCRTPoly>> result(iteration);

    if(num==1){
        for(usint i=0; i< list.size(); i++){
            result[i] = Indicator(ciphertext, bound, rounds, list[i]);
            result[i] = RotAndSum(result[i], size ,1);
        }
    }else{
        for(usint i=0; i< iteration; i++){
            Plaintext checker = GenIndicatorCheckerPartialArray(i*num, size, cc, list);
            result[i] = IndicatorSIMD(ciphertext, bound, rounds, checker);
            result[i] = RotAndSum(result[i], size ,1);
        }
    }
    
    return result;
}



vector<Ciphertext<DCRTPoly>> IDF(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint bound, const usint size, const vector<usint> list){
    const auto cc = ciphertext[0]->GetCryptoContext();
    auto rounds = GenZeroTestRounds(size, cc->GetCryptoParameters()->GetPlaintextModulus());
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    double num = (double)(batchSize/size); //number of document

    vector<Ciphertext<DCRTPoly>> result(ciphertext.size());

    
    for(usint i=0; i< ciphertext.size(); i++){
        //Getting DF
        result[i] = ZeroTest(ciphertext[i], size, rounds);
        result[i] = cc->EvalSub(result[i], 1);
        cc->EvalNegateInPlace(result[i]);
        result[i] = RotAndSum(result[i], batchSize ,size);

    //     result[i] = cc->EvalAdd(result[i], 1);
    //     result[i] = cc->EvalMult(result[i], 1/num);
    //     cc->ModReduceInPlace(result[i]);
    //     result[i] = EvalInverse(result[i], num, 4);

    //     result[i] = EvalLogLike(result[i], num);

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



vector<Ciphertext<DCRTPoly>> IDFMult(const vector<Ciphertext<DCRTPoly>> ciphertext, const int32_t size, const vector<Plaintext> idf) {
	
    const auto cc = ciphertext[1]->GetCryptoContext();
    // auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    vector<Ciphertext<DCRTPoly>> result(ciphertext.size()-1);


    for(usint i=1;i<ciphertext.size();i++){

        result[i-1] = cc->EvalMult(ciphertext[i], idf[i-1]);
        cc->ModReduceInPlace(result[i-1]);
        // result[i-1] = RotAndSum(tmp, -batchSize, -size);
    }
    

    return result;
}



vector<Ciphertext<DCRTPoly>> DistanceComparison(const vector<Ciphertext<DCRTPoly>> ciphertext, const int32_t size, const vector<Plaintext> tfidf){
    const auto cc = ciphertext[0]->GetCryptoContext();
    // auto batchSize = cc->GetEncodingParams()->GetBatchSize();
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
    results[0] = RotAndSum(result, size, 1);



    const double divisor = 256;
    const double threshold = 4;
    cout << "Threshold: " << threshold << endl;
    result = cc->EvalSub(results[0], threshold);
    result = cc->EvalMult(result, 1 / divisor);
    cc->ModReduceInPlace(result);

    results[1] = comp(result, divisor, false, false);
    result = cc->EvalPoly(results[1], {1,-0.5,-0.5});
    results[2] = Cleanse(result);

    
    // vector<double> maskmsg(batchSize);
    // // for(usint i=0;i<batchSize;i++){
    // //     maskmsg[i]=0.0;
    // // }
    // for(usint i=0;i<batchSize/size;i++){
    //     maskmsg[i*size]=1.0;
    // }
    // Plaintext mask = cc->MakeCKKSPackedPlaintext(maskmsg);

    // result = cc->EvalMult(result, mask);
    // cc->ModReduceInPlace(result);
    // result = RotAndSum(result, -size, -1);


    // results[2] = cc->EvalMult(result, text);
    // cc->ModReduceInPlace(results[2]);


    return results;
}

Ciphertext<DCRTPoly> Retrieval(const Ciphertext<DCRTPoly> ciphertext, const int32_t size, Plaintext text){
    const auto cc = ciphertext->GetCryptoContext();
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    Ciphertext<DCRTPoly> result;
    // vector<Ciphertext<DCRTPoly>> results(3);

    // for(usint i=0;i<ciphertext.size();i++){
    //     Ciphertext<DCRTPoly> tmp = cc->EvalSub(ciphertext[i], tfidf[i]);
    //     tmp = cc->EvalMult(tmp,tmp);
    //     cc->ModReduceInPlace(tmp);
        
    //     if(i==0){
    //         result = tmp->Clone();
    //     }else{
    //         result = cc->EvalAdd(tmp,result);
    //     }
    // }
    // results[0] = RotAndSum(result, size, 1);



    // const double divisor = 256;
    // const double threshold = 4;
    // cout << "Threshold: " << threshold << endl;
    // result = cc->EvalSub(results[0], threshold);
    // result = cc->EvalMult(result, 1 / divisor);
    // cc->ModReduceInPlace(result);

    // results[1] = comp(result, divisor, false, false);
    // result = cc->EvalPoly(results[1], {1,-0.5,-0.5});
    // result = Cleanse(result);


    vector<double> maskmsg(batchSize);
    // for(usint i=0;i<batchSize;i++){
    //     maskmsg[i]=0.0;
    // }
    for(usint i=0;i<batchSize/size;i++){
        maskmsg[i*size]=1.0;
    }
    Plaintext mask = cc->MakeCKKSPackedPlaintext(maskmsg);

    result = cc->EvalMult(ciphertext, mask);
    cc->ModReduceInPlace(result);
    result = RotAndSum(result, -size, -1);


    result = cc->EvalMult(result, text);
    cc->ModReduceInPlace(result);


    return result;
}

vector<Plaintext> RawTFIDF(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize, const vector<double> tf, const vector<double> idf){
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


Plaintext loadtext(const CryptoContext<DCRTPoly> cc, const usint size, const double scale){
    vector<double> textraw = readtexts(size, "reviewtext_amazon.txt", scale);
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    vector<double> slice(batchSize);
    for(usint i=0; i<batchSize; i++){
        slice[i]=textraw[i];
    }
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(slice);
    
    return ptxt;
}

vector<Plaintext> loadtfidf(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize){
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

vector<Plaintext> loadidf(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize, const bool copy, const usint padidx){
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


vector<Plaintext> loadquery(const CryptoContext<DCRTPoly> cc, const usint base, const usint dim, const usint size, const usint batchSize, const usint idx){
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


vector<Plaintext> loadquerytf(const CryptoContext<DCRTPoly> cc, const usint packlen, const usint maxlen, const usint numvocab, const usint batchSize, const usint idx){
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


}