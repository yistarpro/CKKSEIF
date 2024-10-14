
#ifndef EIF_UTILS_H
#define EIF_UTILS_H

#include "openfhe.h"
#include <iostream>
#include <map>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

    // //----------------------------------------------------------------------------------
	// //   Copy & Repeat of Messages in Plaintext
	// //----------------------------------------------------------------------------------

	// //size of vals=valsSize. copy vals fully on slot.
	// //(a,b,c) to (a,b,c,a,b,c,a,b,c...)
	vector<double> fullCopy(const vector<double> vals, const usint batchSize, const usint valsSize);

	// //size of vals= batchSize/repeatnum. repeat each value in vals #repeatnum times.
	// //(a,b,c) to (a,a.a,b,b,b,c,c,c,...)
	vector<double> repeat(const vector<double> vals, const usint batchSize, const usint repeatnum);

	// //pad
	// complex<double>* padcomplex(complex<double>* vals, long current, long batchSize);

    // //----------------------------------------------------------------------------------
	// //   Read & Write
	// //----------------------------------------------------------------------------------

	// //Getting Weight of Compression
	vector<double> getWeight(const usint outputdimension, const usint mk, const string path="data/6B50d8_8weight.txt");

	vector<double> getWeightLogreg(const usint outputdimension, const string path="data/6B50d8_8weight.txt");


	// //Getting Word Index of Compression
	map<string, vector<usint>> getWordindex(const usint m, const string path="data/6B50d8_8wordtoindex.txt");
	map<usint, string> getIndexToWord(const string path);

	// //Getting Original Embedding
	// static map<string, complex<double>*> getEmb(long numfeature);


	// //Import and Export of the Evaluation Results

	// //Write down the result of Coded Embedding Evaluation 
	// static void writePt(string* plain, complex<double>* result,long n, long vectorsize, long m, long k,long repeatnum, long numfeature);
	// static void addPt(complex<double>* result,long n, long vectorsize, long m, long k,long repeatnum, long numfeature);


	// //Write down the result of Coded Embedding Evaluation 
	// static void codedwritePt(string* plain, complex<double>* result,long n, long m, long k, long numfeature);
	// static void codedaddPt(complex<double>* result,long n, long m, long k, long numfeature);


	// //Read the result of Coded Embedding Evaluation 
	// static map<string, complex<double>*> readresult(long numfeature, long m, long k,long repeatnum);


	// //Utility of Word

	// //Sample words for test from Word Embedding Indices
	// Plaintext samplestring(const usint numofsamples, const usint batchSize, const usint interval, string path="../data/6B50d8_8wordtoindex.txt");

	// //From sentence of size n to a message vector. Note: batchSize/m*k*repeatnum = n
	// static void foldstring(string sentence, string* msgvec, long n);

	//reading word formed texts
	vector<string> readsentence(const usint size, usint batchblocknum, usint batchblocksize, const string path="../data/sentences.txt");

	vector<usint> readlabels(usint batchblocknum, usint batchblocksize, const string path="../data/sentences.txt");


	//reading indice formed texts
	vector<double> readtexts(const usint size, const string filename,  const double scale=1, const double pad=1023);

	void writetext(const Plaintext inputtext, const usint size, const string filename, const double scale=1);

	void mapandwritetext(const Plaintext inputtext, const usint size, const string filename, const double scale=1);



    // //----------------------------------------------------------------------------------
	// //   Error Estimation
	// //----------------------------------------------------------------------------------

	vector<double> randomRealArray(const usint size, const double bound = 1.0);

	vector<double> randomIntArray(const usint size, const usint bound);

	vector<double> randomIntArrayNoised(const usint size, const usint bound, const usint noiselevel);

	vector<usint> fixedIntArray(const usint size, const usint bound);

	vector<double> randomForRound(const usint size, const usint bound, const usint precision);

	vector<double> randomDiscreteArray(const usint size, const usint bound);

	vector<double> fixedDiscreteArray(const usint size, const usint bound);

	void paramcheck(const CryptoContext<DCRTPoly> cc);

	void bootSet1(CCParams<CryptoContextCKKSRNS> parameters, const usint scaleModSize);
	void bootSet2(CryptoContext<DCRTPoly> cc, const PrivateKey<DCRTPoly> privateKey, const usint batchSize);


	// //Outputs precision level
	void precision(const Plaintext vals, const vector<double> vals2, const usint size);
	usint precisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const usint interval);
	void compprecision(const Ciphertext<DCRTPoly> ciphertext, const vector<double> vals2, const usint size, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys);


	// //Precision when the result is only 0, 1
	void binaryprecision(const Plaintext vals, const usint size);

	double countprecisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const bool show=false);
	double countSIMDprecisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const bool show=false);

	double CodedcountprecisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const bool show=false);

	double countprecisionPartilMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const vector<usint> list, const bool show=false);
	double CodedcountprecisionPartialMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const vector<usint> list, const bool show=false);


	void binaryprecisiontrack(const Plaintext vals, const usint size, const vector<double> origin);


	usint argmaxerror(const Plaintext vals, const usint size);
	usint argmax(const Plaintext vals, const usint size);
	void roundprecision(const vector<double> vals1, const vector<double> vals2, const usint size);


}
#endif
