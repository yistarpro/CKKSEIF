#ifndef EIF_ALGORITHMS_LOOKUP
#define EIF_ALGORITHMS_LOOKUP

#include "openfhe.h"
#include "embedding.h"
#include <iostream>
#include <map>


using namespace lbcrypto;
using namespace std;

namespace ckkseif {

    //----------------------------------------------------------------------------------
	//   Look-Up Table
	//----------------------------------------------------------------------------------
	
	// //Encrypt for LUT-SIMD, n=valsnum*numcode*bound*featurenum
	Ciphertext<DCRTPoly> EncryptForSIMD(const vector<double> vals, const usint bound, const PublicKey<DCRTPoly> publicKey, CryptoContext<DCRTPoly> cc);

	vector<Ciphertext<DCRTPoly>> HELUT_LT(const Ciphertext<DCRTPoly> ciphertexts, const vector<double> table, const usint bound, const usint outputdimension);

	vector<Ciphertext<DCRTPoly>> HELUT_CI(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension);
	
	vector<Ciphertext<DCRTPoly>> CodedHELUT(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension);

	vector<Ciphertext<DCRTPoly>> CodedHELUT_P1(const Ciphertext<DCRTPoly> ciphertext, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension);

	//----------------------------------------------------------------------------------
	//   Logistic Regression
	//----------------------------------------------------------------------------------
	
	Ciphertext<DCRTPoly> EncryptSentenceSIMD(const CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly> publicKey, const vector<string> sentence, CompressedEmbedding model);

	Ciphertext<DCRTPoly> InferenceEncryptedSIMD(const vector<Ciphertext<DCRTPoly>> ciphertexts, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg);

	vector<Ciphertext<DCRTPoly>> EncryptSentence(const CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly> publicKey, const vector<string> sentence, CompressedEmbedding model);

	Ciphertext<DCRTPoly> InferenceEncrypted(const vector<Ciphertext<DCRTPoly>> ciphertexts, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg);

	vector<vector<double>> SentenceEmbeddingPlain(const CryptoContext<DCRTPoly> cc, const vector<string> sentence, CompressedEmbedding model);

	vector<double> InferencePlain(const CryptoContext<DCRTPoly> cc, vector<vector<double>> emb, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg);

}

#endif
