#ifndef EIF_ALGORITHMS_H
#define EIF_ALGORITHMS_H

#include "openfhe.h"
#include "embedding.h"
#include <iostream>
#include <map>


using namespace lbcrypto;
using namespace std;

namespace ckkseif {

//class ALGORITHMS {

//public:
	//----------------------------------------------------------------------------------
	//   ADVANCED HOMOMORPHIC OPERATIONS
	//----------------------------------------------------------------------------------


    void AddRotKeyForEmb(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t mk);

    void AddRotKeyForIR(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t size, const int32_t batchSize);

    void AddRotKeyForPo2(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t batchSize);

    void AddRotKeyForCountSIMD(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const usint base, const int32_t size,  const int32_t batchSize, const usint bound);


    void AddRotKeyForSort(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t size);

    void AddRotKeyForkSorter(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t k);

    void AddRotKeyForBoot(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t size);

	Ciphertext<DCRTPoly> BootAuto(const Ciphertext<DCRTPoly> ciphertext);

	Ciphertext<DCRTPoly> Product(const vector<Ciphertext<DCRTPoly>> ciphertext);

	Ciphertext<DCRTPoly> RotSlow(const Ciphertext<DCRTPoly> ciphertext, const int32_t i, const usint size);

	Ciphertext<DCRTPoly> RotSlowMinus(const Ciphertext<DCRTPoly> ciphertext, const int32_t i, const usint size);


    Ciphertext<DCRTPoly> EvalLog(const Ciphertext<DCRTPoly> ciphertext, const double bound, const double base, const usint degree);

    Ciphertext<DCRTPoly> EvalLogLike(const Ciphertext<DCRTPoly> ciphertext, const double bound);

    Ciphertext<DCRTPoly> EvalInverse(const Ciphertext<DCRTPoly> ciphertext, const double bound, const usint degree);

    // Ciphertext<DCRTPoly> EvalInverse(const Ciphertext<DCRTPoly> ciphertext, const double bound){
	// 	return EvalInverse(ciphertext, bound, 4+log2(bound));
	// }


	vector<double> GetCoeff(const usint bound);

    Plaintext GenIndicatorChecker(const usint bound, const CryptoContext<DCRTPoly> cc);

    Plaintext GenIndicatorCheckerInterval(const usint from, const usint size, const CryptoContext<DCRTPoly> cc);

	//gen pt filled with: from ~ to-1
    Plaintext GenIndicatorCheckerIntervalRecursive(const usint from, const usint to, const usint size, const CryptoContext<DCRTPoly> cc);

	//gen pt filled with: [slicelength * iter] * size, [slicelength * iter + 1] * size .....
	Plaintext GenIndicatorCheckerForSort(const usint size, const CryptoContext<DCRTPoly> cc, const usint iter);

	//gen pt filled with: from ~ to-1
    vector<Plaintext> GenIndicatorCheckerForSIMDCOUNT(const usint base, const usint size, const usint paral, const CryptoContext<DCRTPoly> cc);


    Plaintext GenIndicatorCheckerPartialArray(const usint from, const usint size, const CryptoContext<DCRTPoly> cc, const vector<usint> list);


	//Set indicator rounds for plaintext modulus 35,40,45,50,59
    vector<usint> GenIndicatorRounds(const usint bound, const usint scaleModSize);

	//Set indicator rounds for plaintext modulus 35,40,45,50,59 - not optimized 
    vector<usint> GenZeroTestRounds(const usint bound, const usint scaleModSize);


    Ciphertext<DCRTPoly> RotAndSum(const Ciphertext<DCRTPoly> ciphertext, const int32_t from, const int32_t to);
    //16 to 1 : sum up 16 slots
	//Col Sum: RotAndSum(ciphertext, size, 1);
	//Row Sum: RotAndSum(ciphertext, sizesquare, size);
	//Transpose Row to Col: RotAndSum(ciphertext, -(sizesquare-size), -(size-1));
	//Transpose Col to Row: RotAndSum(ciphertext, sizesquare-size, size-1);
	//Copy Col: RotAndSum(ciphertext, -size, -1);
	//Copy Row: RotAndSum(ciphertext, -sizesquare, -size);
	//fullCopy: RotAndSum(ciphertext, -batchSize, -size);


	Ciphertext<DCRTPoly> Cleanse(const Ciphertext<DCRTPoly> ciphertext, const usint round=1);

	Ciphertext<DCRTPoly> Indicator(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const double numtocheck);

	//Indcator for sort, checking entry of M_comp equal 0. For domain -1, 0, 1, only 0 maps to 1.
	Ciphertext<DCRTPoly> IndicatorBinary(const Ciphertext<DCRTPoly> ciphertext, const vector<usint> rounds);

	Ciphertext<DCRTPoly> IndicatorSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const Plaintext numtocheck);

	Ciphertext<DCRTPoly> ZeroTest(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds);


	//----------------------------------------------------------------------------------
	//   LUT
	//----------------------------------------------------------------------------------
	
	// //Encrypt for LUT-SIMD, n=valsnum*numcode*bound*featurenum
	Ciphertext<DCRTPoly> encryptForSIMD(const vector<double> vals, const usint bound, const PublicKey<DCRTPoly> publicKey, CryptoContext<DCRTPoly> cc);

	vector<Ciphertext<DCRTPoly>> lookUpTableLT(const Ciphertext<DCRTPoly> ciphertexts, const vector<double> table, const usint bound, const usint outputdimension);

	vector<Ciphertext<DCRTPoly>> lookUpTableCI(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension);
	
	vector<Ciphertext<DCRTPoly>> lookUpTable(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension);

	vector<Ciphertext<DCRTPoly>> lookUpTableSIMD(const Ciphertext<DCRTPoly> ciphertext, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension);


	// //Sentence to code, then encrypt
	// void WordEncrypt(Ciphertext& cipher, string* vals, long n, long logp, long logq, WordCompression& model, long repeatnum);
	// void codedWordEncrypt(Ciphertext* cipher, string* vals, long n, long logp, long logq, WordCompression& model);

	//----------------------------------------------------------------------------------
	//   Logistic Regression
	//----------------------------------------------------------------------------------
	Ciphertext<DCRTPoly> encrypt_sentence_SIMD(const CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly> publicKey, const vector<string> sentence, CompressedEmbedding model);

	Ciphertext<DCRTPoly> inference_encrypted_SIMD(const vector<Ciphertext<DCRTPoly>> ciphertexts, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg);

	vector<Ciphertext<DCRTPoly>> encrypt_sentence(const CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly> publicKey, const vector<string> sentence, CompressedEmbedding model);

	Ciphertext<DCRTPoly> inference_encrypted(const vector<Ciphertext<DCRTPoly>> ciphertexts, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg);

	vector<vector<double>> sentencembedding_plain(const CryptoContext<DCRTPoly> cc, const vector<string> sentence, CompressedEmbedding model);

	vector<double> inference_plain(const CryptoContext<DCRTPoly> cc, vector<vector<double>> emb, const usint length, const vector<usint> lengthvec, CompressedEmbedding model, LogregModel logreg);


	//----------------------------------------------------------------------------------
	//   Comparison & Another Indicator & Parity
	//----------------------------------------------------------------------------------
	Ciphertext<DCRTPoly> normalize(const Ciphertext<DCRTPoly> ciphertext, const double bound);

	Ciphertext<DCRTPoly> comparison(const Ciphertext<DCRTPoly> ciphertext, const usint degf, const usint degg, const double bound, const usint ver);

	//optimized comparison
	Ciphertext<DCRTPoly> comp(const Ciphertext<DCRTPoly> ciphertext, const double bound=1.0, const bool boot=false, const bool lastmod=false);
	
	Ciphertext<DCRTPoly> compandUp(const Ciphertext<DCRTPoly> ciphertext, const double bound, const bool boot, const usint up);

	Ciphertext<DCRTPoly> compDecrete(const Ciphertext<DCRTPoly> ciphertext, const int32_t bound);

	Ciphertext<DCRTPoly> fakeboot(const Ciphertext<DCRTPoly> ciphertext, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys);

	Ciphertext<DCRTPoly> boot(const Ciphertext<DCRTPoly> ciphertext, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys);

	Ciphertext<DCRTPoly> discreteEqualZero(const Ciphertext<DCRTPoly> ciphertext, const usint d, const usint K);

	
	Ciphertext<DCRTPoly> IndicatorByLagrange(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<double> coeff);

	Ciphertext<DCRTPoly> Parity(const Ciphertext<DCRTPoly> ciphertext, const usint d);

	Ciphertext<DCRTPoly> ParityBySin(const Ciphertext<DCRTPoly> ciphertext, const usint d, const usint K);


	Ciphertext<DCRTPoly> ExtractMSB(const Ciphertext<DCRTPoly> ciphertext, const usint bound);

	Ciphertext<DCRTPoly> ExtractLSB(const Ciphertext<DCRTPoly> ciphertext, const usint bound);

	vector<Ciphertext<DCRTPoly>> ExtractMSBs(const Ciphertext<DCRTPoly> ciphertext, const usint bound, usint iter);

	vector<Ciphertext<DCRTPoly>> ExtractLSBs(const Ciphertext<DCRTPoly> ciphertext, const usint bound, usint iter);

	
	vector<Ciphertext<DCRTPoly>> DecompToBits(const Ciphertext<DCRTPoly> ciphertext, const usint boundbits, const usint maxdepth);
		
	vector<Ciphertext<DCRTPoly>> BitsToOHE(const vector<Ciphertext<DCRTPoly>> ciphertext);

	vector<Ciphertext<DCRTPoly>> BitsToOHESIMD(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint size);


	// //----------------------------------------------------------------------------------
	// //   Counting
	// //----------------------------------------------------------------------------------


	vector<vector<usint>> GenIndices(const usint exponent, const usint exponentbound, const bool maximalmode=false);

	vector<Ciphertext<DCRTPoly>> MakeBasisBlock(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint level, vector<vector<usint>> indices, const bool maximalmode=false);

	//maximalmode=true: aim base^dim dimensional basis. Only required for ngram.
	vector<Ciphertext<DCRTPoly>> MakeBasis(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint exponentbound, const bool maximalmode=false);




	vector<vector<double>> MakeBasisBlockTrack(const usint inputbits, const usint batchSize, const usint base, const usint size, const usint iter);


	vector<Ciphertext<DCRTPoly>> ToOHESIMD(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size);

	vector<Ciphertext<DCRTPoly>> FullBasis(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint size);

	vector<Ciphertext<DCRTPoly>> MakeBasisBlockSIMD(const vector<Ciphertext<DCRTPoly>> ciphertext,const usint base, const usint size, const usint paral, const usint leftover, const usint level, vector<vector<usint>> indices, const bool maximalmode=false);

	vector<Ciphertext<DCRTPoly>> MakeBasisSIMD(const vector<Ciphertext<DCRTPoly>> ciphertext,const usint base, const usint size, const usint exponentbound, const bool maximalmode=false);




	vector<Ciphertext<DCRTPoly>> ToOHE(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base);


	// vector<Ciphertext<DCRTPoly>> MakeBasisFromOHE(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint base, const usint iter=4);


	vector<Ciphertext<DCRTPoly>> Count(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const usint gather);

	vector<Ciphertext<DCRTPoly>> CountSIMD(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint rotsumsize, const usint exponent);


	vector<Ciphertext<DCRTPoly>> CountPartial(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const vector<usint> list);

	vector<Ciphertext<DCRTPoly>> NaiveCount(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size);

	vector<Ciphertext<DCRTPoly>> NaiveCountSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size);

	vector<Ciphertext<DCRTPoly>> NaiveCountPartial(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint size, const vector<usint> list);

	//operate gather before IDF to compress ciphertext
	vector<Ciphertext<DCRTPoly>> IDF(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint bound, const usint size, const vector<usint> list);

	
	
	vector<Ciphertext<DCRTPoly>> NgramBasis(const vector<Ciphertext<DCRTPoly>> basis, const usint n);

	vector<Ciphertext<DCRTPoly>> Ngram(const vector<Ciphertext<DCRTPoly>> basis, const usint base, const usint size, const usint exponent, const usint exponentbound, const usint n, const double ratio=100, const bool maximalmode=false);

	vector<Ciphertext<DCRTPoly>> IDFMult(const vector<Ciphertext<DCRTPoly>> ciphertext, const int32_t size, const vector<Plaintext> idf);

	vector<Ciphertext<DCRTPoly>> DistanceComparison(const vector<Ciphertext<DCRTPoly>> ciphertext, const int32_t size, const vector<Plaintext> tfidf);

	Ciphertext<DCRTPoly> Retrieval(const Ciphertext<DCRTPoly> ciphertext, const int32_t size, const Plaintext text);


	vector<Plaintext> RawTFIDF(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize, const vector<double> tf, const vector<double> idf);

	Plaintext loadtext(const CryptoContext<DCRTPoly> cc, const usint size, const double scale);

	vector<Plaintext> loadtfidf(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize);

	vector<Plaintext> loadidf(const CryptoContext<DCRTPoly> cc, const usint size, const usint vocabsize, const usint batchSize, const bool copy, const usint padidx);

	vector<Plaintext> loadquery(const CryptoContext<DCRTPoly> cc, const usint base, const usint dim, const usint size, const usint batchSize, const usint idx);

	vector<Plaintext> loadquerytf(const CryptoContext<DCRTPoly> cc, const usint packlen, const usint maxlen, const usint numvocab, const usint batchSize, const usint idx);

	// //----------------------------------------------------------------------------------
	// //   Sorting
	// //----------------------------------------------------------------------------------

	// void rotAndSumLeft(Ciphertext& res, Ciphertext& cipher, long from, long to);
	// void rotAndSumRight(Ciphertext& res, Ciphertext& cipher, long from, long to);

	// void maskRow(Ciphertext& res, Ciphertext& cipher, long logsize, long logp);
	// void maskCol(Ciphertext& res, Ciphertext& cipher, long logsize, long logp);

	// void copyRow(Ciphertext& res, Ciphertext& cipher, long logsize, bool mask, long logp);

	// void copyCol(Ciphertext& res, Ciphertext& cipher, long logsize, bool mask, long logp);

	// void transposeCol(Ciphertext& res, Ciphertext& cipher, long logsize, bool mask, long logp);

	// void transposeRow(Ciphertext& res, Ciphertext& cipher, long logsize, bool mask, long logp);

	// void rowSum(Ciphertext& res, Ciphertext& cipher, long logsize);

	// void sort(Ciphertext& res, Ciphertext& cipher, long size, long logp, long mod);

	vector<Plaintext> maskPrecompute(const usint size, const usint batchSize, const CryptoContext<DCRTPoly> cc);

	vector<Plaintext> maskPrecompute_full(const usint size, const usint batchSize, const CryptoContext<DCRTPoly> cc);


	Ciphertext<DCRTPoly> sort(const Ciphertext<DCRTPoly> ciphertext, const int32_t size,  const int32_t bound, const usint scaleModSize, const KeyPair<DCRTPoly> keys, const bool boot1, const bool boot2);

	Ciphertext<DCRTPoly> sort_full(const Ciphertext<DCRTPoly> ciphertext, const int32_t size,  const int32_t bound, const usint scaleModSize, const KeyPair<DCRTPoly> keys, const bool boot1, const bool boot2);


	// //----------------------------------------------------------------------------------
	// //   Sorting_baseline
	// //----------------------------------------------------------------------------------

	Ciphertext<DCRTPoly> Max(const Ciphertext<DCRTPoly> arrA, const Ciphertext<DCRTPoly> arrB, const usint bound);

	Ciphertext<DCRTPoly> localRot(const Ciphertext<DCRTPoly> ciphertext, const usint rotation, const usint interval);

	vector<Ciphertext<DCRTPoly>> decomp(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint num, const usint ciphernum, const usint interval);

	Ciphertext<DCRTPoly> gather(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint num, const usint interval);

	vector<Ciphertext<DCRTPoly>> SorterDecomposed2(const vector<Ciphertext<DCRTPoly>> ciphertext);

	vector<Ciphertext<DCRTPoly>> SorterDecomposed3(const vector<Ciphertext<DCRTPoly>> ciphertext);

	vector<Ciphertext<DCRTPoly>> SorterDecomposed5(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint bound, const usint interval);

	Ciphertext<DCRTPoly> kSorter(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const usint k, const usint interval);

	// Ciphertext<DCRTPoly> mthMaxDecomposed(const vector<Ciphertext<DCRTPoly>> arrA, const vector<Ciphertext<DCRTPoly>> arrB, const vector<Ciphertext<DCRTPoly>> comp, const int32_t sizeA, const int32_t sizeB, const usint m, const usint bound, const usint interval);


	// Ciphertext<DCRTPoly> mthMax(const Ciphertext<DCRTPoly> arrA, const int32_t sizeA, const Ciphertext<DCRTPoly> arrB, const int32_t sizeB, const usint m, const usint bound);




	// //----------------------------------------------------------------------------------
	// //   AES evaluation
	// //----------------------------------------------------------------------------------

	// vector<Ciphertext<DCRTPoly>> KeyAdditionInit(const vector<Ciphertext<DCRTPoly>> ciphertext);

	// vector<Ciphertext<DCRTPoly>> AESRound(const vector<Ciphertext<DCRTPoly>> ciphertext);

	// vector<Ciphertext<DCRTPoly>> KeyAddition(const vector<Ciphertext<DCRTPoly>> ciphertext);

	Ciphertext<DCRTPoly> EvalBinaryBootstrap(const Ciphertext<DCRTPoly> ciphertext);


}
#endif
