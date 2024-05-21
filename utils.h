
#ifndef EIF_UTILS_H
#define EIF_UTILS_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

    // //----------------------------------------------------------------------------------
	// //   Copy & Repeat of Messages in Plaintext
	// //----------------------------------------------------------------------------------

	// //size of vals=valsSize. copy vals fully on slot.
	// //(a,b,c) to (a,b,c,a,b,c,a,b,c...)
	vector<double> fullCopy(const vector<double> vals, const usint batchSize, const usint valsSize);

	// //size of vals= batchSize/repeatnum. repeat each value in vals #copy times.
	// //(a,b,c) to (a,a.a,b,b,b,c,c,c,...)
	vector<double> repeat(const vector<double> vals, const usint batchSize, const usint repeatnum);

	// //pad
	// complex<double>* padcomplex(complex<double>* vals, long current, long batchSize);

    // //----------------------------------------------------------------------------------
	// //   Read & Write
	// //----------------------------------------------------------------------------------

	// //Getting Weight of Compression
	vector<double> getWeight(const usint outputdimension, const usint mk, const string path="data/6B50d8_8weight.txt");

    // //----------------------------------------------------------------------------------
	// //   Error Estimation
	// //----------------------------------------------------------------------------------

	vector<double> randomRealArray(const usint size, const double bound = 1.0);

	vector<double> randomIntArray(const usint size, const usint bound);

	vector<double> randomDiscreteArray(const usint size, const usint bound);

	vector<double> fixedDiscreteArray(const usint size, const usint bound);

	void paramcheck(const CryptoContext<DCRTPoly> cc);


	// //Outputs precision level
	void precision(const Plaintext vals, const vector<double> vals2, const usint size);
	usint precisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const usint interval);
	void compprecision(const Ciphertext<DCRTPoly> ciphertext, const vector<double> vals2, const usint size, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys);


	// //Precision when the result is only 0, 1
	void binaryprecision(const Plaintext vals, const usint size);

}
#endif
