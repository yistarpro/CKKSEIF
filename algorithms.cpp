#include "openfhe.h"
#include "utils.h"
#include "embedding.h"
#include "algorithms.h"
#include <iostream>
#include <vector>
#include <cmath>
#include "math/chebyshev.h"
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

void AddRotKeyForSort(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t size){
    int32_t sizesquare=size*size;
    int32_t sizesquare2=size*size-size;
    int32_t interval = 2*log2(size);
    
    std::vector<int32_t> arr(interval*3);
    for(int32_t i = 0 ; i < interval ; i++){
        sizesquare >>= 1;
        arr[i]=(sizesquare);
        arr[i+interval]= -(sizesquare);
    }
    for(usint i = 0 ; i < log2(size) ; i++){
        sizesquare2 >>= 1;
        arr[i+2*interval]= (sizesquare2);
        arr[i+2*interval+log2(size)]= -(sizesquare2);
    }
    cc->EvalRotateKeyGen(privateKey, arr);
}

void AddRotKeyForkSorter(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t k){
    std::vector<int32_t> arr(2*k-2);
    for(int32_t i = 1 ; i < k ; i++){
        arr[i-1]=-(i);
        arr[k+i-2]=(i);
    }
    cc->EvalRotateKeyGen(privateKey, arr);
}

void AddRotKeyForBoot(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t size){
    int32_t sizesquare=size*size;
    int32_t sizesquare2=size*size-size;
    int32_t interval = 2*log2(size);
    
    std::vector<int32_t> arr(interval*3);
    for(int32_t i = 0 ; i < interval ; i++){
        sizesquare >>= 1;
        arr[i]=(sizesquare);
        arr[i+interval]= -(sizesquare);
    }
    for(usint i = 0 ; i < log2(size) ; i++){
        sizesquare2 >>= 1;
        arr[i+2*interval]= (sizesquare2);
        arr[i+2*interval+log2(size)]= -(sizesquare2);
    }
    cc->EvalRotateKeyGen(privateKey, arr);
}

Ciphertext<DCRTPoly> BootAuto(Ciphertext<DCRTPoly> ciphertext){
    const auto cc = ciphertext->GetCryptoContext();
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
                    restmp[k] += table[base+ j*model.m + model.wordtoindex[sentence[k]][j]];
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

Ciphertext<DCRTPoly> compandUp(const Ciphertext<DCRTPoly> ciphertext, const double bound, const bool boot,  const usint up){
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

Ciphertext<DCRTPoly> compDecrete(const Ciphertext<DCRTPoly> ciphertext, const int32_t bound){
    const auto cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> input=cc->EvalAdd(ciphertext, bound);
    Ciphertext<DCRTPoly> tmp;
    auto scalingfactor = cc->GetEncodingParams()->GetPlaintextModulus();

    vector<usint> rounds=GenIndicatorRounds(2*bound,scalingfactor);
    Ciphertext<DCRTPoly> result=Indicator(input, 2*bound, rounds, (double)bound);
    result = cc->EvalMult(result,0.5);
    cc->ModReduceInPlace(result);

    for(int32_t j=bound+1; j< 2*bound-1; j++){
	    tmp = Indicator(input, 2*bound, rounds, (double)j);        
        result = cc->EvalAdd(result, tmp);
    }
	
    return result;
}

Ciphertext<DCRTPoly> fakeboot(const Ciphertext<DCRTPoly> ciphertext, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys){
    Plaintext result;
    cc->Decrypt(keys.secretKey, ciphertext, &result);
    vector<double> x1 = result->GetRealPackedValue();
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    return c1;
}

Ciphertext<DCRTPoly> boot(const Ciphertext<DCRTPoly> ciphertext, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys){
    Plaintext result;
    cc->Decrypt(keys.secretKey, ciphertext, &result);
    vector<double> x1 = result->GetRealPackedValue();
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    return c1;
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


Ciphertext<DCRTPoly> Parity(const Ciphertext<DCRTPoly> ciphertext, const usint d){
    const auto cc = ciphertext->GetCryptoContext();

    Ciphertext<DCRTPoly> sincipher = ParityBySin(ciphertext, d, 8);
    auto ptmod = cc->GetCryptoParameters()->GetPlaintextModulus();
    usint iter = 1;
    if(ptmod < 41){
        if(d>6)iter+=1;
    }
    if(d>9)iter+=1;
    sincipher = Cleanse(sincipher, iter);
    return sincipher;
}


Ciphertext<DCRTPoly> ParityBySin(const Ciphertext<DCRTPoly> ciphertext, const usint d, const usint K){
    const auto cc = ciphertext->GetCryptoContext();
    double bound = (double)(1 << (d-1));
    const double PI = 3.1415926 / 2;
    double div = 1/bound;
    Ciphertext<DCRTPoly> norm = cc->EvalSub(ciphertext, bound); 
    norm = cc->EvalMult(norm, div); 
    cc->ModReduceInPlace(norm);
    Ciphertext<DCRTPoly> coscipher = cc->EvalChebyshevFunction([PI](double x) -> double { return std::cos(x*PI);}, norm,-1 , 1, K);
    Ciphertext<DCRTPoly> sincipher = cc->EvalChebyshevFunction([PI](double x) -> double {return std::sin(x*PI); }, norm,-1 , 1, K);

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
    const auto cc = ciphertext->GetCryptoContext();
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
    const auto cc = ciphertext->GetCryptoContext();
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
    const auto cc = ciphertext->GetCryptoContext();
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

vector<Ciphertext<DCRTPoly>> DecompToBits(const Ciphertext<DCRTPoly> ciphertext, const usint boundbits, const usint maxdepth){
    const auto cc = ciphertext->GetCryptoContext();
    Ciphertext<DCRTPoly> tmp = ciphertext->Clone();
    vector<Ciphertext<DCRTPoly>> result(boundbits);
    usint currentbits = boundbits; //left bits to extract
    usint LSBptr = 0;
    usint MSBptr = boundbits-1;
    vector<usint> MSBbudget = {0,0,17,17,17, 21 , 21, 25 , 25, 29,29};
    vector<usint> LSBbudget = {0,0,10,11,12,13,14,15,16,17,20};

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

// vector<Ciphertext<DCRTPoly>> DecompToBits(const Ciphertext<DCRTPoly> ciphertext, const usint boundbits){
//     const auto cc = ciphertext->GetCryptoContext();
//     Ciphertext<DCRTPoly> tmp = ciphertext->Clone();
//     vector<Ciphertext<DCRTPoly>> result(boundbits);
//     usint bound=1 << boundbits;

//     usint half = boundbits / 2;
//     usint left = boundbits % 2; 
//     for(usint i=0; i< half; i++){
//         result[boundbits-1-i] = ExtractMSB(tmp, bound);
//         result[i] = ExtractLSB(tmp, bound);
//         tmp = cc->EvalSub(tmp, result[boundbits-1-i]);
//         tmp = cc->EvalSub(tmp, result[i]);
//         cc->EvalMultInPlace(result[boundbits-1-i], 1/((double)(bound/2)));
//         cc->ModReduceInPlace(result[boundbits-1-i]);
//         //Cleanse

//         tmp = cc->EvalMult(tmp, 0.5);
//         cc->ModReduceInPlace(tmp);
//         bound /=4;
//         std::cout << "Estimated level:  " << i << "th: " <<  result[i]->GetLevel() << std::endl;
//         std::cout << "Estimated level: " << boundbits-1-i << "th: " << result[boundbits-1-i]->GetLevel() << std::endl;
//         std::cout << "Estimated level:  " << "tmp: " <<  tmp->GetLevel() << std::endl;

//         //if(???)cc->EvalBootstrap();
//     }

//     if(left == 1){
//         result[half] = tmp;
//         //Cleanse
//     }

//     return result;
// }

// vector<Ciphertext<DCRTPoly>> DecompToBitsOptimized(const Ciphertext<DCRTPoly> ciphertext, const usint boundbits){
//     return ciphertext;

// }






vector<Ciphertext<DCRTPoly>> BitsToOHE(const vector<Ciphertext<DCRTPoly>> ciphertext){
    const auto cc = ciphertext[0]->GetCryptoContext();
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
    const auto cc = ciphertext[0]->GetCryptoContext();
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    usint num = ciphertext.size();
    vector<Ciphertext<DCRTPoly>> result(num);
    Ciphertext<DCRTPoly> tmp;

    Plaintext pt = GenIndicatorCheckerIntervalRecursive(0, 2, size, cc);


    for(usint i=0;i< num ; i++){
        result[i] = RotAndSum(ciphertext[i], -batchSize, -2*size);
        tmp = cc->EvalSub(ciphertext[i], pt);
        cc->EvalNegateInPlace(tmp);
        result[i] = cc->EvalRotate(result[i], size);
        cc->EvalAddInPlace(result[i],tmp);        
    }
    return result;
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



// vector<vector<double>> MakeBasisBlockTrack(const usint inputbits, const usint batchSize, const usint base, const usint size, const usint iter){
//     const usint paral = batchSize/size; //Capability of SIMD
//     usint num = base*inputbits/log2(base); //initial ciphertext number
//     usint currentbase = base;
//     usint res=0;
//     usint div = currentbase/paral;
//     usint divnum=div;
//     if(div == 0)divnum=1;

//     vector<vector<double>> result0(num*divnum+res);
//     for(usint i=0; i<num; i++){
//         for(usint j=0; j< divnum; j++){
//             if(div!=0){
//                 vector<double> tmp(paral);
//                 for(usint k=0; k< paral; k++){
//                     tmp[k]=j*paral+k;
//                 }
//                 result0[i*divnum+j]=tmp;
//             }else{
//                 vector<double> tmp(base);
//                 for(usint k=0; k< base; k++){
//                     tmp[k]=k;
//                 }
//                 result0[i]=tmp;
//             }
            
//         }
//     }
//     if(iter==0)return result0;

//     //update
//     num = num*divnum;
//     usint phase = (num/divnum)/2;
//     res = num - phase * 2 * divnum;

//     // for(usint iteration=1;iteration<iter+1; iteration++){

//     //     vector<vector<double>> result1((currentbase*divnum)*(phase)+res);
//     //     for(usint i=0; i<num; i++){
//     //         for(usint j=0; j< divnum; j++){
//     //             if(div!=0){
//     //                 vector<double> tmp(paral);
//     //                 for(usint k=0; k< paral; k++){
//     //                     tmp[k]=j*paral+k;
//     //                 }
//     //                 result0[i*divnum+j]=tmp;
//     //             }else{
//     //                 vector<double> tmp(base);
//     //                 for(usint k=0; k< base; k++){
//     //                     base[k]=k;
//     //                 }
//     //                 result0[i]=tmp;
//     //             }
                
//     //         }
//     //     }
//     // //     return result1;



//     // }

//     return result0;

// }


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


vector<Plaintext> maskPrecompute(const int32_t size, const usint batchSize, const CryptoContext<DCRTPoly> cc){
    vector<Plaintext> result(3);
	vector<double> masking(batchSize);
    usint sizesquare = size*size;

    //vertical mask : Extract Column
	for(usint s=0; s<batchSize; s++){
		masking[s]=0.0;
	}
	for(usint i=0; i<(batchSize/sizesquare);i++){
		usint interval=i*(sizesquare);
		for(int32_t s=0; s<size; s++){
			masking[interval+s*size]=1.0;
		}
	}
	
    result[0] = cc->MakeCKKSPackedPlaintext(masking);

    //horizontal mask : Extract Row
	for(usint s=0; s<batchSize; s++){
		masking[s]=0.0;
	}
	for(usint i=0; i<(batchSize/sizesquare);i++){
		usint interval=i*(sizesquare);
		for(int32_t s=0; s<size; s++){
			masking[interval+s]=1.0;
		}
	}
    
    result[1] = cc->MakeCKKSPackedPlaintext(masking);

    //skew mask
	for(usint s=0; s<batchSize; s++){
		masking[s]=0.5;
	}
	for(usint i=0; i<(batchSize/sizesquare);i++){
		usint interval=i*(sizesquare);
		for(int32_t s=0; s<size; s++){
			masking[interval+s*size+s]=0.0; //diagonal entries
		}
		for(int32_t s=0; s<size; s++){
			for(int32_t t=0; t<s; t++){
				masking[interval+s*size+t]=-0.5; //lowertriangle
			}
		}
	}

    result[2] = cc->MakeCKKSPackedPlaintext(masking);

    return result;
}


vector<Plaintext> maskPrecompute_full(const int32_t size, const usint batchSize, const CryptoContext<DCRTPoly> cc){
    vector<Plaintext> result(3);
	vector<double> masking(batchSize);
    usint sizesquare = size*size;

    //vertical mask : Extract Column
	for(usint s=0; s<batchSize; s++){
		masking[s]=0.0;
	}
    for(int32_t s=0; s<size; s++){
		masking[s*size]=1.0;
	}
	for(usint i=1; i<(batchSize/sizesquare);i++){
		usint interval=i*(sizesquare);
		for(int32_t s=0; s<size; s++){
			masking[interval+s*size]=1.0;
		}
	}
	
    result[0] = cc->MakeCKKSPackedPlaintext(masking);

    //horizontal mask : Extract Row
	for(usint s=0; s<batchSize; s++){
		masking[s]=0.0;
	}
    for(int32_t s=0; s<size; s++){
		masking[s]=1.0;
	}
	for(usint i=1; i<(batchSize/sizesquare);i++){
		usint interval=i*(sizesquare);
		for(int32_t s=0; s<size; s++){
			masking[interval+s]=1.0;
		}
	}
    
    result[1] = cc->MakeCKKSPackedPlaintext(masking);

    //skew mask
    auto numct = sizesquare / batchSize;
    auto slicelength = size / numct;

    for(usint n=0; n< numct; n++){
        for(usint s=0; s<batchSize; s++){
            masking[s]=0.5;
        }
        usint initpt = n*slicelength;
        for(int32_t s=0; s<slicelength; s++){
            masking[initpt+s*size+s]=0.0; //diagonal entries
        }
        for(int32_t s=0; s<slicelength; s++){
            for(int32_t t=0; t<s+initpt; t++){
                masking[s*size+t]=-0.5; //lowertriangle
            }
        }
        result[2+n] = cc->MakeCKKSPackedPlaintext(masking);
    }
	


    return result;
}




Ciphertext<DCRTPoly> sort(const Ciphertext<DCRTPoly> ciphertext, const int32_t size, const int32_t bound, const usint scaleModSize, const KeyPair<DCRTPoly> keys, const bool boot1, const bool boot2){
	const auto cc = ciphertext->GetCryptoContext();
    auto batchSize = cc->GetRingDimension(); 
    batchSize >>=1;
    auto sizesquare = size*size;

    auto masks = maskPrecompute(size, batchSize, cc);

    Ciphertext<DCRTPoly> tmp, tmp2, copy, result;

    Plaintext pt, ptboot;


    tmp = RotAndSum(ciphertext, -(sizesquare-size), -(size-1)); //transpose row to col
    tmp = cc->EvalMult(tmp, masks[0]);
    cc->ModReduceInPlace(tmp);
    tmp2 =  RotAndSum(tmp, -size, -1); //copy col
    copy =  RotAndSum(ciphertext, -sizesquare, -size); // copy row
    tmp2 = cc->EvalSub(tmp2, copy);

    tmp = comp(tmp2, bound, boot1, true); //obtain M_comp
    // tmp= comparison(tmp2, 0, 3, 1,3);
    // cc->Decrypt(keys.secretKey, tmp, &pt);
    // std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    // pt->SetLength(size);
    // pt->SetLength(8);
    // cout << "before boot during comp : " << pt << endl;

    // if(boot1){
    //     tmp = cc->EvalBootstrap(tmp);
    //     cc->Decrypt(keys.secretKey, tmp, &ptboot);
    //     std::cout << "Estimated level: " << ptboot->GetLevel() << std::endl;
    //     ptboot->SetLength(size);
    //     ptboot->SetLength(8);
    //     cout << "boot during comp : " << ptboot << endl;
    // }
    
    // tmp= comparison(tmp, 2, 0, 1,3);

    // cc->Decrypt(keys.secretKey, tmp, &pt);
    // std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    // binaryprecision(pt, batchSize);
    // pt->SetLength(size);
    // pt->SetLength(8);
    // cout << "comp : " << pt << endl;

    // cc-> EvalAddInPlace(tmp, 1);
    // cc-> EvalMultInPlace(tmp, 0.5);
    // cc-> ModReduceInPlace(tmp);

    result = RotAndSum(tmp, sizesquare, size); // row sum
    result = cc->EvalMult(result, masks[1]);
    cc->ModReduceInPlace(result);
    
    tmp = cc->EvalAdd(tmp, tmp); //subprocess of comparison
    tmp = cc->EvalAdd(tmp, -1); //subprocess of comparison
    
    cc->Decrypt(keys.secretKey, result, &pt);
    std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    pt->SetLength(size);
    pt->SetLength(8);
    cout << "step1: " << pt << endl;

    // result = RotAndSum(result, -(sizesquare-size), -(size-1)); //transpose row to col


    vector<usint> rounds = GenIndicatorRounds(2, scaleModSize);
    tmp2 = IndicatorBinary(tmp, rounds);
    
    cc->Decrypt(keys.secretKey, tmp2, &pt);
    std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    binaryprecision(pt, batchSize);
    pt->SetLength(sizesquare);
    pt->SetLength(8);
    cout << "Binary Indicator: " << pt << endl;

    tmp2 = cc->EvalMult(tmp2, masks[2]);
    cc->ModReduceInPlace(tmp2);
    tmp =  RotAndSum(tmp2, sizesquare, size); //row sum
    cc->EvalAddInPlace(result, tmp);// order vector


    cc->Decrypt(keys.secretKey, result, &pt);
    std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    pt->SetLength(sizesquare);
    pt->SetLength(8);
    cout << "step2: " << pt << endl;
    //result = fakeboot(result, cc, keys);

    tmp = cc->EvalMult(result, masks[1]);
    cc->ModReduceInPlace(tmp);
    tmp = RotAndSum(tmp, -sizesquare, -size); //copy row

    tmp = cc->EvalSub(tmp, 0.5);
    rounds = GenIndicatorRounds(size, scaleModSize);
    Plaintext numstocheck = GenIndicatorCheckerForSort(size, cc, 0);

    // const double div =1 / (double) size;
    // tmp = cc->EvalSub(tmp, numstocheck);
    // cc->EvalMultInPlace(tmp, div);
    // if(boot2==true)tmp = cc->EvalBootstrap(tmp);
    // usint cleanseiter=rounds[1];
    // rounds[1]=0;
    // tmp2 = Indicator(tmp, 1, rounds, 0);
    // if(boot2==true)tmp2 = cc->EvalBootstrap(tmp2);
	// tmp2 = Cleanse(tmp2, cleanseiter);
    tmp2 = IndicatorSIMD(result, size, rounds, numstocheck);
    
    cc->Decrypt(keys.secretKey, tmp2, &pt);
    std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    pt->SetLength(sizesquare);
    pt->SetLength(8);
    cout << "Indicator: " << pt << endl;

    tmp2 = cc->EvalMult(tmp2, copy);
    cc->ModReduceInPlace(tmp2);
    result = RotAndSum(tmp2, size, 1); // col sum


    cc->Decrypt(keys.secretKey, result, &pt);
    std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    pt->SetLength(size);
    cout << "step3: " << pt << endl;


    return result;
}


Ciphertext<DCRTPoly> sort_full(const Ciphertext<DCRTPoly> ciphertext, const int32_t size, const int32_t bound, const usint scaleModSize, const KeyPair<DCRTPoly> keys, const bool boot1, const bool boot2){
	const auto cc = ciphertext->GetCryptoContext();
    auto batchSize = cc->GetRingDimension(); 
    batchSize >>=1;
    auto sizesquare = size*size;
    auto numct = sizesquare / batchSize;
    auto slicelength = size / numct;

    auto masks = maskPrecompute_full(size, batchSize, cc);

    Ciphertext<DCRTPoly> tmp, tmp2, copy, result, pert;
    vector<Ciphertext<DCRTPoly>> tmps(numct);
    vector<Ciphertext<DCRTPoly>> copies(numct);
    // vector<Ciphertext<DCRTPoly>> tmps2(numct);

    Plaintext pt, ptboot;

    for(usint i=0; i<numct; i++){
        tmp = cc->EvalRotate(ciphertext, i*slicelength);
        tmp = RotAndSum(tmp, -(size-1)*slicelength, -(size-1)); //transpose row to col
        tmp = cc->EvalMult(tmp, masks[0]);
        cc->ModReduceInPlace(tmp);
        copies[i] =  RotAndSum(tmp, -size, -1); //copy col
    }

    copy =  RotAndSum(ciphertext, -batchSize, -size); // copy row, Note: size*slicelength = batchSize
    for(usint i=0; i<numct; i++){
        tmp = cc->EvalSub(copies[i], copy);
        tmps[i] = comp(tmp, bound, boot1, true); //obtain M_comp
        if(i==0){
            result = RotAndSum(tmps[i], batchSize, size); // row sum
        }else{
            tmp = RotAndSum(tmps[i], batchSize, size); // row sum
            result = cc->EvalAdd(tmp, result);
        }
    }


    //tmp = comp(tmp2, bound, boot1); //obtain M_comp
    // tmp= comparison(tmp2, 0, 3, 1,3);
    // cc->Decrypt(keys.secretKey, tmp, &pt);
    // std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    // pt->SetLength(size);
    // pt->SetLength(8);
    // cout << "before boot during comp : " << pt << endl;

    // if(boot1){
    //     tmp = cc->EvalBootstrap(tmp);
    //     cc->Decrypt(keys.secretKey, tmp, &ptboot);
    //     std::cout << "Estimated level: " << ptboot->GetLevel() << std::endl;
    //     ptboot->SetLength(size);
    //     ptboot->SetLength(8);
    //     cout << "boot during comp : " << ptboot << endl;
    // }
    
    // tmp= comparison(tmp, 2, 0, 1,3);

    // cc->Decrypt(keys.secretKey, tmp, &pt);
    // std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    // binaryprecision(pt, batchSize);
    // pt->SetLength(size);
    // pt->SetLength(8);
    // cout << "comp : " << pt << endl;

    // cc-> EvalAddInPlace(tmp, 1);
    // cc-> EvalMultInPlace(tmp, 0.5);
    // cc-> ModReduceInPlace(tmp);
    
    tmp = cc->EvalAdd(tmp, tmp); //subprocess of comparison
    tmp = cc->EvalAdd(tmp, -1); //subprocess of comparison
    
    // cc->Decrypt(keys.secretKey, result, &pt);
    // std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    // pt->SetLength(size);
    // pt->SetLength(8);
    // cout << "step1: " << pt << endl;

    vector<usint> rounds = GenIndicatorRounds(2, scaleModSize);

    for(usint i=0; i<numct; i++){
        tmp = cc->EvalAdd(tmps[i], tmps[i]); //subprocess of comparison
        tmp = cc->EvalAdd(tmp, -1); //subprocess of comparison
        tmp = IndicatorBinary(tmp, rounds); ///Check!!!!
        
        tmp = cc->EvalMult(tmp, masks[2+i]);
        if(i==0){
            pert = RotAndSum(tmp, batchSize, size); //row sum
        }else{
            tmp =  RotAndSum(tmp, batchSize, size); //row sum
            pert = cc->EvalAdd(pert,tmp);
        }
    }
    cc->ModReduceInPlace(pert);

    result = cc->EvalAdd(result, pert);
    result = cc->EvalMult(result, masks[1]);
    cc->ModReduceInPlace(result);

    
    // cc->Decrypt(keys.secretKey, tmp2, &pt);
    // std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    // binaryprecision(pt, batchSize);
    // pt->SetLength(sizesquare);
    // pt->SetLength(8);
    // cout << "Binary Indicator: " << pt << endl;




    // cc->Decrypt(keys.secretKey, result, &pt);
    // std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    // pt->SetLength(sizesquare);
    // pt->SetLength(8);
    // cout << "step2: " << pt << endl;
    //result = fakeboot(result, cc, keys);

    result = RotAndSum(result, -batchSize, -size); //copy row

    result = cc->EvalSub(result, 0.5);
    rounds = GenIndicatorRounds(size, scaleModSize);

    vector<Ciphertext<DCRTPoly>> results(numct);
    for(usint i=0; i<numct; i++){
        Plaintext numstocheck = GenIndicatorCheckerForSort(size, cc, i);
        tmp2 = IndicatorSIMD(result, size, rounds, numstocheck);
        tmp2 = cc->EvalMult(tmp2, copy);
        cc->ModReduceInPlace(tmp2);
        results[i] = RotAndSum(tmp2, size, 1); // col sum
    }


    // const double div =1 / (double) size;
    // tmp = cc->EvalSub(tmp, numstocheck);
    // cc->EvalMultInPlace(tmp, div);
    // if(boot2==true)tmp = cc->EvalBootstrap(tmp);
    // usint cleanseiter=rounds[1];
    // rounds[1]=0;
    // tmp2 = Indicator(tmp, 1, rounds, 0);
    // if(boot2==true)tmp2 = cc->EvalBootstrap(tmp2);
	// tmp2 = Cleanse(tmp2, cleanseiter);

    // cc->Decrypt(keys.secretKey, tmp2, &pt);
    // std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    // pt->SetLength(sizesquare);
    // pt->SetLength(8);
    // cout << "Indicator: " << pt << endl;


    // cc->Decrypt(keys.secretKey, result, &pt);
    // std::cout << "Estimated level: " << pt->GetLevel() << std::endl;
    // pt->SetLength(size);
    // cout << "step3: " << pt << endl;


    return result;
}




Ciphertext<DCRTPoly> Max(const Ciphertext<DCRTPoly> arrA, const Ciphertext<DCRTPoly> arrB, const usint bound){
    const auto cc = arrA->GetCryptoContext();
    Ciphertext<DCRTPoly> tmpA, result;

    tmpA = cc->EvalSub(arrA, arrB);
    result = comp(tmpA, bound, false, true);

    result = cc->EvalMult(result, tmpA);
    cc->ModReduceInPlace(result);
    result = cc->EvalAdd(result, arrB);

    return result;
}

Ciphertext<DCRTPoly> localRot(const Ciphertext<DCRTPoly> ciphertext, const usint rotation, const usint interval) {
    const auto cc = ciphertext->GetCryptoContext();
    auto batchSize = cc->GetRingDimension(); 
    batchSize >>=1;
    Ciphertext<DCRTPoly> tmp, result;
    Plaintext maskA, maskB;
	vector<double> maskingA(batchSize);
    vector<double> maskingB(batchSize);

	for(usint s=0; s<batchSize; s++){
		maskingA[s]=0.0;
        maskingB[s]=1.0;
	}
	for(usint i=0; i<(batchSize/interval);i++){
		usint base=i*(interval);
		for(usint s=0; s<rotation; s++){
			maskingA[base+s]=1.0;
            maskingB[base+s]=0.0;
		}
	}
    maskA = cc->MakeCKKSPackedPlaintext(maskingA);
    maskB = cc->MakeCKKSPackedPlaintext(maskingB);

    tmp = cc->EvalMult(ciphertext, maskA);
    tmp = cc->EvalRotate(tmp, -rotation);
    result = cc->EvalMult(ciphertext, maskB);
    result = cc->EvalRotate(result, rotation);
    result = cc->EvalAdd(result,tmp);
    cc->ModReduceInPlace(result);

    return result;
}

vector<Ciphertext<DCRTPoly>> decomp(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint num, const usint ciphernum, const usint interval){
    const auto cc = ciphertext[0]->GetCryptoContext();
    auto batchSize = cc->GetRingDimension(); 
    batchSize >>=1;
    vector<double> masking(batchSize);

    for(usint s=0; s<batchSize; s++){
		masking[s]=0.0;
	}
	for(usint i=0; i<(batchSize/interval);i++){
		masking[i*interval]=1.0;
	}
    Plaintext mask = cc->MakeCKKSPackedPlaintext(masking);

    vector<Ciphertext<DCRTPoly>> results(num*ciphernum);
    for(usint s=0;s<ciphernum;s++){
        results[num*s]=cc->EvalMult(ciphertext[s], mask);
        cc->ModReduceInPlace(results[num*s]);

        for(usint i=1; i<num; i++){
            results[num*s+i]= cc->EvalRotate(ciphertext[s], i);
            results[num*s+i]= cc->EvalMult(results[num*s+i], mask);
            cc->ModReduceInPlace(results[num*s+i]);
        }
    }
    

    return results;
}

Ciphertext<DCRTPoly> gather(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint num, const usint interval){
    const auto cc = ciphertext[0]->GetCryptoContext();
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();

    vector<double> masking(batchSize);
    for(usint s=0; s<batchSize; s++){
		masking[s]=0.0;
	}
	for(usint i=0; i<(batchSize/interval);i++){
		masking[i*interval]=1.0;
	}
    Plaintext mask = cc->MakeCKKSPackedPlaintext(masking);


    Ciphertext<DCRTPoly> result=cc->EvalMult(ciphertext[0], mask);    
    Ciphertext<DCRTPoly> tmp;
    for(usint i=1; i<num; i++){
        tmp = cc->EvalMult(ciphertext[i], mask);
        tmp = cc->EvalRotate(tmp, -i);
        result = cc->EvalAdd(result, tmp);
    }
    cc->ModReduceInPlace(result);

    return result;
}


vector<Ciphertext<DCRTPoly>> SorterDecomposed2(const vector<Ciphertext<DCRTPoly>> ciphertext){
    const auto cc = ciphertext[0]->GetCryptoContext();

    Ciphertext<DCRTPoly> tmpA = cc->EvalSub(ciphertext[0], ciphertext[1]);
    vector<Ciphertext<DCRTPoly>> result(2);
    
    cout << "check" << endl;

    tmpA = cc->EvalMult(ciphertext[2], tmpA);
    cc->ModReduceInPlace(tmpA);
    result[0] = cc->EvalAdd(tmpA, ciphertext[1]);
    result[1] = cc->EvalSub(ciphertext[0],tmpA);

    return result;
}


vector<Ciphertext<DCRTPoly>> SorterDecomposed3(const vector<Ciphertext<DCRTPoly>> ciphertext){
    const auto cc = ciphertext[0]->GetCryptoContext();

    Ciphertext<DCRTPoly> tmpA = cc->EvalSub(ciphertext[0], ciphertext[1]);
    vector<Ciphertext<DCRTPoly>> result(3);

    tmpA = cc->EvalMult(ciphertext[3], tmpA);
    cc->ModReduceInPlace(tmpA);
    result[0] = cc->EvalAdd(tmpA, ciphertext[1]);
    result[1] = cc->EvalSub(ciphertext[0],tmpA);

    //tmpA = cc->EvalPoly(ciphertext[3], {1,-2,2}); //update ciphertext[3]

    //If ciphertext[3] == 0, Swap cipher [4], [5] to 1-[5], 1-[4]
    Ciphertext<DCRTPoly> tmp = cc->EvalAdd(ciphertext[4], ciphertext[5]);
    tmp = cc->EvalSub(tmp, 1);
    tmp = cc->EvalMult(ciphertext[3], tmp);
    cc->ModReduceInPlace(tmp);
    tmp = cc->EvalAdd(tmp, 1);
    Ciphertext<DCRTPoly> tmpB = cc->EvalSub(tmp, ciphertext[5]);
    Ciphertext<DCRTPoly> tmpC = cc->EvalSub(tmp, ciphertext[4]);

    //compare 1st and 3rd
    tmp = cc->EvalSub(ciphertext[2], result[0]);
    tmp = cc->EvalMult(tmpC, tmp);
    cc->ModReduceInPlace(tmp);
    result[0] = cc->EvalAdd(tmp, result[0]);

    //compare 2nd and 3rd
    tmp = cc->EvalSub(result[1], ciphertext[2]); 
    tmp = cc->EvalMult(tmpB, tmp);   
    cc->ModReduceInPlace(tmp);
    result[2] = cc->EvalSub(result[1], tmp);
    
    tmp= cc->EvalAdd(ciphertext[0], ciphertext[1]);
    result[1]= cc->EvalAdd(tmp, ciphertext[2]);
    result[1] = cc->EvalSub(result[1],result[0]);
    result[1] = cc->EvalSub(result[1],result[2]);    

    return result;
}


vector<Ciphertext<DCRTPoly>> SorterDecomposed5(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint bound, const usint interval){
    const auto cc = ciphertext[0]->GetCryptoContext();

    Ciphertext<DCRTPoly> tmp, tmp8, tmp12;
    vector<Ciphertext<DCRTPoly>> result(5);
    //vector<Ciphertext<DCRTPoly>> tmp(15);

    //Sort cipher[0] [1]
    tmp = cc->EvalSub(ciphertext[0], ciphertext[1]);

    tmp = cc->EvalMult(ciphertext[5], tmp);
    cc->ModReduceInPlace(tmp);
    result[0] = cc->EvalAdd(tmp, ciphertext[1]);
    result[1] = cc->EvalSub(ciphertext[0],tmp);

    // //Update ciphertext[5]
    // tmp[0] = cc->EvalPoly(ciphertext[3], {1,-2,2});

    // //Update comparison results
    // //If ciphertext[5] == 0, Swap cipher [6], [10]
    // tmp = cc->EvalSub(ciphertext[6], ciphertext[10]);
    // tmp = cc->EvalMult(ciphertext[5], tmp);
    // cc->ModReduceInPlace(tmp);
    // tmp[6] = cc->EvalAdd(ciphertext[10], tmp);
    // tmp[10] = cc->EvalSub(ciphertext[6], tmp);

    // //If ciphertext[5] == 0, Swap cipher [11], [13] to 1-[13], 1-[11]
    // tmp = cc->EvalAdd(ciphertext[11], ciphertext[13]);
    // tmp = cc->EvalSub(tmp, 1);
    // tmp = cc->EvalMult(ciphertext[5], tmp);
    // cc->ModReduceInPlace(tmp);
    // tmp = cc->EvalAdd(tmp, 1);
    // tmp[11] = cc->EvalSub(tmp, ciphertext[13]);
    // tmp[13] = cc->EvalSub(tmp, ciphertext[11]);

    // //If ciphertext[5] == 0, Swap cipher [9], [14] to [14], [9]
    // tmp = cc->EvalSub(ciphertext[9], ciphertext[14]);
    // tmp = cc->EvalMult(ciphertext[5], tmp);
    // cc->ModReduceInPlace(tmp);
    // tmp[9] = cc->EvalAdd(ciphertext[14], tmp);
    // tmp[14] = cc->EvalSub(ciphertext[9], tmp);

    //////
    //Sort cipher[2] [3] [4]
    //Sort [2] [3]
    tmp = cc->EvalSub(ciphertext[2], ciphertext[3]);
    tmp = cc->EvalMult(ciphertext[7], tmp);
    cc->ModReduceInPlace(tmp);
    result[2] = cc->EvalAdd(tmp, ciphertext[3]);
    result[3] = cc->EvalSub(ciphertext[2],tmp);

    // //Update ciphertext[7]
    // tmp[7] = cc->EvalPoly(ciphertext[7], {1,-2,2});

    //If ciphertext[7] == 0, Swap cipher [8], [12] to [12], [8]
    tmp = cc->EvalSub(ciphertext[8], ciphertext[12]);
    tmp = cc->EvalMult(ciphertext[7], tmp);
    cc->ModReduceInPlace(tmp);
    tmp8 = cc->EvalAdd(tmp, ciphertext[12]);
    tmp12 = cc->EvalSub(ciphertext[8],tmp);

    //compare 3rd and 5th
    tmp = cc->EvalSub(result[2], ciphertext[4]); 
    tmp = cc->EvalMult(tmp12, tmp);   
    cc->ModReduceInPlace(tmp);
    result[2] = cc->EvalAdd(ciphertext[4], tmp);

    //compare 4th and 5th
    tmp = cc->EvalSub(result[3], ciphertext[4]); 
    tmp = cc->EvalMult(tmp8, tmp);   
    cc->ModReduceInPlace(tmp);
    result[4] = cc->EvalSub(result[3], tmp);
    
    tmp= cc->EvalAdd(ciphertext[2], ciphertext[3]);
    result[3]= cc->EvalAdd(tmp, ciphertext[4]);
    result[3] = cc->EvalSub(result[3],result[2]);
    result[3] = cc->EvalSub(result[3],result[4]);    

    /////////
    tmp =  gather(result, 5, interval);

    vector<Ciphertext<DCRTPoly>> rot(3);
    rot[0]=tmp->Clone();

    for(usint i=1;i<3;i++){
        rot[i]=localRot(tmp, i, interval);
        rot[i] = cc->EvalSub(tmp, rot[i]);
        rot[i] = comp(rot[i], bound, false, true);
    }
    vector<Ciphertext<DCRTPoly>> decomposed = decomp(rot, 5, 3, interval);

    //////////Merge 0,1 and 2,3,4

    //Compare [0],[2]
    tmp = cc->EvalSub(decomposed[0], decomposed[2]); 
    tmp = cc->EvalMult(decomposed[10], tmp);   
    cc->ModReduceInPlace(tmp);
    result[0] = cc->EvalAdd(decomposed[2], tmp);

    //Find Second
    //If decomposed[10]==1, max [1] [2]
    tmp = cc->EvalSub(decomposed[1], decomposed[2]); 
    tmp = cc->EvalMult(decomposed[6], tmp);   
    cc->ModReduceInPlace(tmp);
    result[1] = cc->EvalAdd(decomposed[2], tmp);

    //If decomposed[10]==0, max [0] [3]
    tmp = cc->EvalSub(decomposed[3], decomposed[0]); 
    tmp = cc->EvalMult(decomposed[13], tmp);
    cc->ModReduceInPlace(tmp);
    result[2] = cc->EvalAdd(decomposed[0], tmp);

    tmp = cc->EvalSub(result[1], result[2]); 
    tmp = cc->EvalMult(decomposed[10], tmp);
    cc->ModReduceInPlace(tmp);
    result[1] = cc->EvalAdd(result[2], tmp);

    ////////////

    //Compare [1],[4]
    tmp = cc->EvalSub(decomposed[4], decomposed[1]); 
    tmp = cc->EvalMult(decomposed[14], tmp);   
    cc->ModReduceInPlace(tmp);
    result[4] = cc->EvalSub(decomposed[4], tmp);

    //Find Second
    //If decomposed[14]==0, min [1] [3]
    tmp = cc->EvalSub(decomposed[3], decomposed[1]); 
    tmp = cc->EvalMult(decomposed[11], tmp);
    cc->ModReduceInPlace(tmp);
    result[3] = cc->EvalAdd(decomposed[1], tmp);

    //If decomposed[14]==1, min [0] [4]
    tmp = cc->EvalSub(decomposed[0], decomposed[4]); 
    tmp = cc->EvalMult(decomposed[9], tmp);
    cc->ModReduceInPlace(tmp);
    result[2] = cc->EvalAdd(decomposed[4], tmp);

    tmp = cc->EvalSub(result[2], result[3]); 
    tmp = cc->EvalMult(decomposed[14], tmp);
    cc->ModReduceInPlace(tmp);
    result[3] = cc->EvalAdd(result[3], tmp);

    /////
    tmp= cc->EvalAdd(ciphertext[1], ciphertext[2]);
    tmp= cc->EvalAdd(ciphertext[0], tmp);
    result[2]= cc->EvalAdd(ciphertext[3], ciphertext[4]);
    result[2]= cc->EvalAdd(tmp, result[2]);


    tmp= cc->EvalAdd(result[0], result[1]);
    result[2] = cc->EvalSub(result[2],tmp);
    tmp= cc->EvalAdd(result[3], result[4]);
    result[2] = cc->EvalSub(result[2],tmp);

    return result;
}



Ciphertext<DCRTPoly> kSorter(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint k, const usint interval){
    const auto cc = ciphertext->GetCryptoContext();

    Ciphertext<DCRTPoly> tmp, tmpA, tmpB;
    vector<Ciphertext<DCRTPoly>> rot(1+k/2);
    rot[0]=ciphertext->Clone();
    if(k==1)return rot[0];


    for(usint i=1;i<1+k/2;i++){
        rot[i]=localRot(ciphertext, i, interval);
        rot[i] = cc->EvalSub(ciphertext, rot[i]);
        rot[i] = comp(rot[i], bound, false, true);
    }

    vector<Ciphertext<DCRTPoly>> decomposed = decomp(rot, k, 1+k/2, interval);

    vector<Ciphertext<DCRTPoly>> tmpresult(k);
    if(k==2)tmpresult = SorterDecomposed2(decomposed);
    if(k==3)tmpresult = SorterDecomposed3(decomposed);
    if(k==5)tmpresult = SorterDecomposed5(decomposed, bound, interval);

    Ciphertext<DCRTPoly> result =  gather(tmpresult, k, interval);


    return result;

}


// Ciphertext<DCRTPoly> mthMaxDecomposed(const vector<Ciphertext<DCRTPoly>> arrA, const vector<Ciphertext<DCRTPoly>> arrB, const vector<Ciphertext<DCRTPoly>> comp, const int32_t sizeA, const int32_t sizeB, const usint m, const usint bound, const usint interval){
//     const auto cc = arrA->GetCryptoContext();
//     if(sizeA==0){
//         return arrB[m-1];
//     }
//     if(sizeB==0){
//         return arrA[m-1];
//     }
//     int32_t i = m/2;
//     int32_t j = m-i;
//     vector<Ciphertext<DCRTPoly>> subarrAformer, subarrAlatter, subarrBformer, subarrBlatter;
//     int32_t sizeAformer, sizeAlatter, sizeBformer, sizeBlatter;
//     if(i < sizeA){
//         sizeAformer=i;
//         sizeAlatter=sizeA-i;
//     }else{
//         sizeAformer=sizeA;
//         sizeAlatter=0;
//     }
//     if(j < sizeB){
//         sizeBformer=j;
//         sizeBlatter=sizeB-j;
//     }else{
//         sizeBformer=sizeB;
//         sizeBlatter=0;
//     }

//     for(int32_t s=0; s<sizeAformer;s++){
//         subarrAformer[s]=arrA[s]->Clone();
//     }
//     for(int32_t s=0; s<sizeAlatter;s++){
//         subarrAlatter[s]=arrA[sizeAformer+s]->Clone();
//     }
//     for(int32_t s=0; s<sizeBformer;s++){
//         subarrBformer[s]=arrB[s]->Clone();
//     }
//     for(int32_t s=0; s<sizeBlatter;s++){
//         subarrBlatter[s]=arrB[sizeAformer+s]->Clone();
//     }

//     auto left = mthMaxDecomposed(subarrAlatter, subarrBformer, const vector<Ciphertext<DCRTPoly>> comp, sizeAlatter, sizeBformer, j, bound, interval);
//     auto right = mthMaxDecomposed(subarrAformer, subarrBlatter, const vector<Ciphertext<DCRTPoly>> comp, sizeAformer, sizeBlatter, i, bound, interval);
    
//     Ciphertext<DCRTPoly> tmp = cc->EvalSub(left, right);

//     Ciphertext<DCRTPoly> result = cc->EvalMult(compLR, tmp);
//     cc->ModReduceInPlace(result);
//     result = cc->EvalAdd(result, right);
    
//     return result;


// }



// Ciphertext<DCRTPoly> mthMax(const Ciphertext<DCRTPoly> arrA, const int32_t sizeA, const Ciphertext<DCRTPoly> arrB, const int32_t sizeB, const usint m, const usint bound){
//     const auto cc = arrA->GetCryptoContext();
//     auto batchSize = cc->GetRingDimension(); 
//     batchSize >>=1;

//     Ciphertext<DCRTPoly> tmp, tmpA, tmpB, result;
    



//     Max(arrA);

//     return result;

// }

Ciphertext<DCRTPoly> EvalBinaryBootstrap(const Ciphertext<DCRTPoly> ciphertext){
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    auto cc        = ciphertext->GetCryptoContext();
    uint32_t M     = cc->GetCyclotomicOrder();
    uint32_t L0    = cryptoParams->GetElementParams()->GetParams().size();



    auto elementParamsRaised = *(cryptoParams->GetElementParams());

    // For FLEXIBLEAUTOEXT we raised ciphertext does not include extra modulus
    // as it is multiplied by auxiliary plaintext
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        elementParamsRaised.PopLastParam();
    }

    auto paramsQ = elementParamsRaised.GetParams();
    usint sizeQ  = paramsQ.size();

    std::vector<NativeInteger> moduli(sizeQ);
    std::vector<NativeInteger> roots(sizeQ);
    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }
    auto elementParamsRaisedPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);

    // uint32_t slots = ciphertext->GetSlots();

    // NativeInteger q = elementParamsRaisedPtr->GetParams()[0]->GetModulus().ConvertToInt();
    // double qDouble  = q.ConvertToDouble();

    // const auto p = cryptoParams->GetPlaintextModulus();
    // double powP  = pow(2, p);

    // int32_t deg = std::round(std::log2(qDouble / powP));
    // uint32_t m_correctionFactor = 0;

    // if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO ||
    //     cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
    //     // The default correction factors chosen yielded the best precision in our experiments.
    //     // We chose the best fit line from our experiments by running ckks-bootstrapping-precision.cpp.
    //     // The spreadsheet with our experiments is here:
    //     // https://docs.google.com/spreadsheets/d/1WqmwBUMNGlX6Uvs9qLXt5yeddtCyWPP55BbJPu5iPAM/edit?usp=sharing
    //     auto tmp = std::round(-0.265 * (2 * std::log2(M / 2) + std::log2(slots)) + 19.1);
    //     if (tmp < 7)
    //         m_correctionFactor = 7;
    //     else if (tmp > 13)
    //         m_correctionFactor = 13;
    //     else
    //         m_correctionFactor = static_cast<uint32_t>(tmp);
    // }
    // else {
    //     m_correctionFactor = 9;
    // }

    // uint32_t correction = m_correctionFactor - deg;


    Ciphertext<DCRTPoly> raised = ciphertext->Clone();
    auto algo                   = cc->GetScheme();
    algo->ModReduceInternalInPlace(raised, raised->GetNoiseScaleDeg() - 1);

    // AdjustCiphertext(raised, correction);
    auto ctxtDCRT = raised->GetElements();

    // We only use the level 0 ciphertext here. All other towers are automatically ignored to make
    // CKKS bootstrapping faster.
    for (size_t i = 0; i < ctxtDCRT.size(); i++) {
        DCRTPoly temp(elementParamsRaisedPtr, COEFFICIENT);
        ctxtDCRT[i].SetFormat(COEFFICIENT);
        temp = ctxtDCRT[i].GetElementAtIndex(0);
        temp.SetFormat(EVALUATION);
        ctxtDCRT[i] = temp;
    }

    raised->SetElements(ctxtDCRT);
    raised->SetLevel(L0 - ctxtDCRT[0].GetNumOfElements());

    Ciphertext<DCRTPoly> result = Parity(raised, 16);

    return result;


}



}