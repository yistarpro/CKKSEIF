#include "openfhe.h"
#include "utils.h"
#include "embedding.h"
#include "algorithms.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <map>
#include <omp.h>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {


//----------------------------------------------------------------------------------
//   LUT
//----------------------------------------------------------------------------------

// HELUT §4.2 — client-side encoding: repeats vals (bound copies each) and encrypts.
Ciphertext<DCRTPoly> EncryptForSIMD(const vector<double> vals, const usint bound, const PublicKey<DCRTPoly> publicKey, CryptoContext<DCRTPoly> cc){
    uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize(); 
	vector<double> copied = repeat(vals, batchSize, bound);

    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(copied);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(publicKey, ptxt1);
    return c1;
}

// HELUT §4.1 / Eq. 9 — HELUT-LT: linear-transformation LUT evaluation T(ct) = E · OHE_p(ct).
vector<Ciphertext<DCRTPoly>> HELUT_LT(const Ciphertext<DCRTPoly> ciphertext, const vector<double> table, const usint bound, const usint outputdimension){
    Ciphertext<DCRTPoly> tmp;
    Ciphertext<DCRTPoly> indresult;
    vector<Ciphertext<DCRTPoly>> result(outputdimension);
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    uint32_t scalingfactor = cc->GetEncodingParams()->GetPlaintextModulus();

    vector<usint> rounds=ParamEEF(bound,scalingfactor);

    TimeVar t;
    double timeind=0.0;

    for(usint j=0; j< bound; j++){
        TIC(t);
        indresult = EEF(ciphertext, bound, rounds, (double)j);
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

// HELUT §4.2 / Alg 3 — HELUT-CI: LUT with coded input, p·l Indicator operations instead of p^l.
// TODO: generalize the reconstruction loop to arbitrary numcode (currently only
// the 2-segment fold is implemented; matches LUTCITest's restriction).
vector<Ciphertext<DCRTPoly>> HELUT_CI(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension){
    if (numcode != 2) {
        cerr << "HELUT_CI: numcode must be 2 (got " << numcode
             << "); reconstruction only implemented for the 2-segment case." << endl;
        return {};
    }

    Ciphertext<DCRTPoly> tmp;
    Ciphertext<DCRTPoly> indresult;
    vector<Ciphertext<DCRTPoly>> basis(bound*numcode);
    vector<Ciphertext<DCRTPoly>> result(outputdimension);
    vector<usint> base(2);
    const usint totalbound = bound * bound;
    const CryptoContext<DCRTPoly> cc = ciphertexts[0]->GetCryptoContext();
    uint32_t scalingfactor = cc->GetEncodingParams()->GetPlaintextModulus();

    vector<usint> rounds=ParamEEF(bound,scalingfactor);

    TimeVar t;
    TIC(t);
    for(usint i=0; i< numcode; i++){
        for(usint j=0; j< bound; j++){
	        basis[i*bound+j] = EEF(ciphertexts[i], bound, rounds, (double)j);
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


// HELUT §4.3 / Alg 4 — CodedHELUT: tensor-compressed LUT evaluation (the main proposal).
vector<Ciphertext<DCRTPoly>> CodedHELUT(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension) {
	Ciphertext<DCRTPoly> tmp;
    vector<Ciphertext<DCRTPoly>> basis(bound*numcode);
    vector<Ciphertext<DCRTPoly>> result(outputdimension);
    const CryptoContext<DCRTPoly> cc = ciphertexts[0]->GetCryptoContext();
    uint32_t scalingfactor = cc->GetEncodingParams()->GetPlaintextModulus();

    vector<usint> rounds=ParamEEF(bound,scalingfactor);

    TimeVar t;
    TIC(t);

    for(usint i=0; i< numcode; i++){
        for(usint j=0; j< bound; j++){
	        basis[i*bound+j] = EEF(ciphertexts[i], bound, rounds, (double)j);
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

// HELUT §4.3 / p1 parallelization — CodedHELUT with codes-of-coded-input ciphertext packing.
vector<Ciphertext<DCRTPoly>> CodedHELUT_P1(const Ciphertext<DCRTPoly> ciphertext, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension) {
	Ciphertext<DCRTPoly> tmp;
    vector<Ciphertext<DCRTPoly>> result;
    const CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
    uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize(); 
    uint32_t scalingfactor = cc->GetEncodingParams()->GetPlaintextModulus();

	usint base;
	vector<double> subtable(bound*numcode);
	vector<double> fulltable(batchSize);

    TimeVar t;
    TIC(t);

    Plaintext numtocheck = GenEEFChecker(bound, cc);
    vector<usint> rounds=ParamEEF(bound,scalingfactor);
	Ciphertext<DCRTPoly> indresult = EEFSIMD(ciphertext, bound, rounds, numtocheck);
	
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
        tmp =  RotSum(tmp, bound*numcode, 1);
        result.push_back(tmp);
	}
	//cout<< "Lookup done: " << result[0]->GetLevel() << endl;
    return result;
}

//----------------------------------------------------------------------------------
//   Logistic Regression
//----------------------------------------------------------------------------------

// HELUT App. E.2 — encrypt a tokenized sentence into a single SIMD-packed ciphertext.
Ciphertext<DCRTPoly> EncryptSentenceSIMD(const CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly> publicKey, const vector<string> sentence, CompressedEmbedding model){
    uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
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
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(publicKey, ptxt);

    return c1;
}


// HELUT App. E.2 — end-to-end encrypted inference (CodedHELUT + LogregModel), SIMD-packed.
Ciphertext<DCRTPoly> InferenceEncryptedSIMD(const vector<Ciphertext<DCRTPoly>> emb, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg) {
    const CryptoContext<DCRTPoly> cc = emb[0]->GetCryptoContext();
    uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    const usint mkl = model.m*model.k*length;
    const usint mk = model.m*model.k;
    const usint numsent = batchSize / mkl;

    // auto emb = CodedHELUT_P1(ciphertexts, model.weight, model.k, model.m, model.outputdimension);


    std::vector<double> weights(batchSize);
    for(usint j=0; j<numsent; j++){
        for(usint k=0; k<length; k++){
            weights[j*mkl+mk*k] = logreg.weight[0] / lengthvec[j];
        }
    }
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(weights);
    Ciphertext<DCRTPoly> res = cc->EvalMult(emb[0], ptxt);

    for(usint i = 0; i< model.outputdimension ; i++){
        for(usint j=0; j<numsent; j++){
            for(usint k=0; k<length; k++){
                weights[j*mkl+mk*k] = logreg.weight[i] / lengthvec[j];
            }
        }
        ptxt = cc->MakeCKKSPackedPlaintext(weights);
        Ciphertext<DCRTPoly> tmp = cc->EvalMult(emb[i], ptxt);
        res = cc->EvalAdd(res, tmp);
    }
    res =  RotSum(res, mkl, mk);
    res = cc->EvalAdd(res, logreg.weight[model.outputdimension]);
    cc->ModReduceInPlace(res);    

    double upperbd = 64;

    res = cc->EvalLogistic(res, -upperbd, upperbd, 128);

    return res;

}


// HELUT App. E.2 — encrypt a tokenized sentence as a vector of ciphertexts (non-SIMD baseline).
vector<Ciphertext<DCRTPoly>> EncryptSentence(const CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly> publicKey, const vector<string> sentence, CompressedEmbedding model){
    uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
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


// HELUT App. E.2 — end-to-end encrypted inference (CodedHELUT + LogregModel), per-token ciphertexts.
Ciphertext<DCRTPoly> InferenceEncrypted(const vector<Ciphertext<DCRTPoly>> emb, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg) {
    const CryptoContext<DCRTPoly> cc = emb[0]->GetCryptoContext();
    uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    // const usint mkl = model.m*model.k*length;
    // const usint mk = model.m*model.k;
    const usint numsent = batchSize / length;

    // auto emb = CodedHELUT_P1(ciphertexts, model.weight, model.k, model.m, model.outputdimension);
    

    std::vector<double> weights(batchSize);
    for(usint j=0; j<numsent; j++){
        for(usint k=0; k<length; k++){
            weights[j*length+k] = logreg.weight[0] / lengthvec[j];
        }
    }
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(weights);
    Ciphertext<DCRTPoly> res = cc->EvalMult(emb[0], ptxt);

    for(usint i = 1; i< model.outputdimension ; i++){
        for(usint j=0; j<numsent; j++){
            for(usint k=0; k<length; k++){
                weights[j*length+k] = logreg.weight[i] / lengthvec[j];
            }
        }
        ptxt = cc->MakeCKKSPackedPlaintext(weights);
        Ciphertext<DCRTPoly> tmp = cc->EvalMult(emb[i], ptxt);
        res = cc->EvalAdd(res, tmp);
    }
    res =  RotSum(res, length, 1);
    res = cc->EvalAdd(res, logreg.weight[model.outputdimension]);
    // cc->ModReduceInPlace(res);

    // double upperbd = 64;

    // res = cc->EvalLogistic(res, -upperbd, upperbd, 128);

    return res;

}

// HELUT App. E.2 (plaintext baseline) — plaintext sentence embedding via the
// same compressed model. Per output dimension i, sums table[base + j*k + idx[j]]
// over the m codebook segments for each word in the sentence.
vector<vector<double>> SentenceEmbeddingPlain(const CryptoContext<DCRTPoly> cc, const vector<string> sentence, CompressedEmbedding model) {
    const uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    const vector<double> &table = model.weight;
    vector<vector<double>> result;

    for (usint i = 0; i < model.outputdimension; i++) {
        const usint base = i * model.m * model.k;
        vector<double> restmp(batchSize);

        for (usint k = 0; k < batchSize; k++) {
            if (model.wordtoindex.find(sentence[k]) == model.wordtoindex.end()) {
                restmp[k] = 0.0;
            } else {
                for (usint j = 0; j < model.m; j++) {
                    restmp[k] += table[base + j * model.k + model.wordtoindex[sentence[k]][j]];
                }
            }
        }
        result.push_back(restmp);
    }
    return result;
}

// HELUT App. E.2 (plaintext baseline) — plaintext inference (sanity check / accuracy reference).
vector<double> InferencePlain(const CryptoContext<DCRTPoly> cc, vector<vector<double>> emb, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg){
    uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    // const usint mkl = model.m*model.k*length;
    // const usint mk = model.m*model.k;
    const usint numsent = batchSize / length;

    // auto emb = CodedHELUT_P1(ciphertexts, model.weight, model.k, model.m, model.outputdimension);
    

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


}