#ifndef EIF_ALGORITHMS_H
#define EIF_ALGORITHMS_H

#include "openfhe.h"
#include "embedding.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

//class ALGORITHMS {

//public:
	//----------------------------------------------------------------------------------
	//   ADVANCED HOMOMORPHIC OPERATIONS
	//----------------------------------------------------------------------------------


    void AddRotKeyForEmb(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t mk);

    Plaintext GenIndicatorChecker(const usint bound, const CryptoContext<DCRTPoly> cc);

	//Set indicator rounds for plaintext modulus 35,40,45,50
    vector<usint> GenIndicatorRounds(const usint bound, const usint scaleModSize);

    Ciphertext<DCRTPoly> RotAndSum(const Ciphertext<DCRTPoly> ciphertext, const int32_t from, const int32_t to);
    //16 to 1 : sum up 16 slots
	//Col Sum: RotAndSum(ciphertext, size, 1);
	//Row Sum: RotAndSum(ciphertext, sizesquare, size);
	//Transpose Row to Col: RotAndSum(ciphertext, -(sizesquare-size), -(size-1));
	//Transpose Col to Row: RotAndSum(ciphertext, sizesquare-size, size-1);
	//Copy Col: RotAndSum(ciphertext, -size, -1);
	//Copy Row: RotAndSum(ciphertext, -sizesquare, -size);


	Ciphertext<DCRTPoly> Cleanse(const Ciphertext<DCRTPoly> ciphertext, const usint round=1);

	Ciphertext<DCRTPoly> Indicator(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const double numtocheck);

	//Indcator for sort, checking entry of M_comp equal 0. For domain -1, 0, 1, only 0 maps to 1.
	Ciphertext<DCRTPoly> IndicatorBinary(const Ciphertext<DCRTPoly> ciphertext, const vector<usint> rounds);

	Ciphertext<DCRTPoly> IndicatorSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const Plaintext numtocheck);

	//----------------------------------------------------------------------------------
	//   LUT
	//----------------------------------------------------------------------------------
	
	// //Encrypt for LUT-SIMD, n=valsnum*numcode*bound*featurenum
	Ciphertext<DCRTPoly> encryptForSIMD(const vector<double> vals, const usint bound, const PublicKey<DCRTPoly> publicKey, CryptoContext<DCRTPoly> cc);

	vector<Ciphertext<DCRTPoly>> lookUpTableLT(const Ciphertext<DCRTPoly> ciphertexts, const vector<double> table, const usint bound, const usint outputdimension);

	vector<Ciphertext<DCRTPoly>> lookUpTableCI(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension);
	
	vector<Ciphertext<DCRTPoly>> lookUpTable(const vector<Ciphertext<DCRTPoly>> ciphertexts, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension);

	vector<Ciphertext<DCRTPoly>> lookUpTableSIMD(const Ciphertext<DCRTPoly> ciphertext, const vector<double> table, const usint bound, const usint numcode, const usint outputdimension);


	//----------------------------------------------------------------------------------
	//   Comparison
	//----------------------------------------------------------------------------------

	Ciphertext<DCRTPoly> comparison(const Ciphertext<DCRTPoly> ciphertext, const usint degf, const usint degg, const double bound, const usint ver);
	//optimized comparison
	Ciphertext<DCRTPoly> comp(const Ciphertext<DCRTPoly> ciphertext, const double bound=1.0, const bool boot=false, const bool lastmod=false);
	
	Ciphertext<DCRTPoly> discreteEqualZero(const Ciphertext<DCRTPoly> ciphertext, const usint d, const usint K);

	vector<double> GetCoeff(const usint bound);

	Ciphertext<DCRTPoly> IndicatorByLagrange(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<double> coeff);


}
#endif
