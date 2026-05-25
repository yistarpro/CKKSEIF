#ifndef EIF_ALGORITHMS_COUNTING
#define EIF_ALGORITHMS_COUNTING

#include "openfhe.h"
#include "embedding.h"
#include "algorithms.h"
#include <iostream>
#include <map>


using namespace lbcrypto;
using namespace std;

namespace ckkseif {

	//----------------------------------------------------------------------------------
	//   Add Rotation Keys for Each Algorithm
	//----------------------------------------------------------------------------------

    void AddRotKeyForIR(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t size, const int32_t batchSize);

    void AddRotKeyForCountSIMD(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const usint base, const int32_t size,  const int32_t batchSize, const usint bound);

	// EEF-checker plaintext generator for the parallel-count pipeline
	// (HECount Alg 7). Moved here from core/include/ckkseif/eif.h because it is
	// hecount-specific: the only caller is ParalBasisExpBlock / CodedCountSIMD.
	vector<Plaintext> GenIndicatorCheckerForSIMDCOUNT(const usint base, const usint size, const usint paral, const CryptoContext<DCRTPoly> cc);

	// //----------------------------------------------------------------------------------
	// //   Counting
	// //----------------------------------------------------------------------------------


	vector<vector<usint>> DimDecomp(const usint exponent, const usint exponentbound, const bool maximalmode=false);

	vector<Ciphertext<DCRTPoly>> BasisExpBlock(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint level, vector<vector<usint>> indices, const bool maximalmode=false);

	//maximalmode=true: aim base^dim dimensional basis. Only required for ngram.
	vector<Ciphertext<DCRTPoly>> BasisExp(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint exponentbound, const bool maximalmode=false);

	vector<Ciphertext<DCRTPoly>> ToOHESIMD(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size);

	vector<Ciphertext<DCRTPoly>> FullBasis(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size);

	vector<Ciphertext<DCRTPoly>> ParalBasisExpBlock(const vector<Ciphertext<DCRTPoly>> ciphertext,const usint base, const usint size, const usint paral, const usint leftover, const usint level, vector<vector<usint>> indices, const bool maximalmode=false);

	vector<Ciphertext<DCRTPoly>> ParalBasisExp(const vector<Ciphertext<DCRTPoly>> ciphertext,const usint base, const usint size, const usint exponentbound, const bool maximalmode=false);

	vector<Ciphertext<DCRTPoly>> ToOHE(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base);

	//Actual Count Algorithm

	vector<Ciphertext<DCRTPoly>> Count(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const usint gather);

	vector<Ciphertext<DCRTPoly>> ParalCount(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint rotsumsize, const usint exponent);

	//Count for subset of the domain
	vector<Ciphertext<DCRTPoly>> CountPartial(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const vector<usint> list);

	vector<Ciphertext<DCRTPoly>> NaiveCount(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size);

	vector<Ciphertext<DCRTPoly>> NaiveCountSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size);

	vector<Ciphertext<DCRTPoly>> NaiveCountPartial(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size, const vector<usint> list);

	// //----------------------------------------------------------------------------------
	// //   Application of Counting Algorithm
	// //----------------------------------------------------------------------------------

	//operate gather before IDF to compress ciphertext
	vector<Ciphertext<DCRTPoly>> IDF(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint bound, const usint size, const vector<usint> list);

	vector<Ciphertext<DCRTPoly>> NgramBasis(const vector<Ciphertext<DCRTPoly>> basis, const usint n);

	vector<Ciphertext<DCRTPoly>> Ngram(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const usint n, const double ratio=100, const bool maximalmode=false);

	vector<Ciphertext<DCRTPoly>> IDFMult(const vector<Ciphertext<DCRTPoly>> ciphertext, const int32_t size, const vector<Plaintext> idf);

	vector<Ciphertext<DCRTPoly>> DistanceComparison(const vector<Ciphertext<DCRTPoly>> ciphertext, const int32_t size, const vector<Plaintext> tfidf);

	Ciphertext<DCRTPoly> Retrieval(const Ciphertext<DCRTPoly> ciphertext, const int32_t size, const Plaintext text);


	vector<Plaintext> PrecomputeTFIDF(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize, const vector<double> tf, const vector<double> idf);

	Plaintext LoadText(const CryptoContext<DCRTPoly> cc, const usint size, const double scale);

	vector<Plaintext> LoadTFIDF(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize);

	vector<Plaintext> LoadIDF(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize, const bool copy, const usint padidx);

	vector<Plaintext> LoadQuery(const CryptoContext<DCRTPoly> cc, const usint base, const usint dim, const usint size, const usint batchSize, const usint idx);

	vector<Plaintext> LoadQueryTF(const CryptoContext<DCRTPoly> cc, const usint packlen, const usint maxlen, const usint numvocab, const usint batchSize, const usint idx);



}
#endif