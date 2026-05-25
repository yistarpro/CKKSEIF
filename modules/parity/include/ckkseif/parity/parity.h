#ifndef CKKSEIF_PARITY_PARITY_H
#define CKKSEIF_PARITY_PARITY_H

#include "openfhe.h"
#include <iostream>
#include <map>


using namespace lbcrypto;
using namespace std;

namespace ckkseif {


	//----------------------------------------------------------------------------------
	//   Parity & Bit Decomposition
	//----------------------------------------------------------------------------------

	// compandUp — sign-function approximation used by ExtractMSB / ExtractLSB.
	Ciphertext<DCRTPoly> compandUp(const Ciphertext<DCRTPoly> ciphertext, const double bound, const bool boot, const usint up);

	Ciphertext<DCRTPoly> Parity(const Ciphertext<DCRTPoly> ciphertext, const usint d);

	Ciphertext<DCRTPoly> ParityBySin(const Ciphertext<DCRTPoly> ciphertext, const usint d, const usint K);

	Ciphertext<DCRTPoly> ExtractMSB(const Ciphertext<DCRTPoly> ciphertext, const usint bound);

	Ciphertext<DCRTPoly> ExtractLSB(const Ciphertext<DCRTPoly> ciphertext, const usint bound);

	vector<Ciphertext<DCRTPoly>> ExtractMSBs(const Ciphertext<DCRTPoly> ciphertext, const usint bound, usint iter);

	vector<Ciphertext<DCRTPoly>> ExtractLSBs(const Ciphertext<DCRTPoly> ciphertext, const usint bound, usint iter);

	
	vector<Ciphertext<DCRTPoly>> DecompToBits(const Ciphertext<DCRTPoly> ciphertext, const usint boundbits, const usint maxdepth);
		
	vector<Ciphertext<DCRTPoly>> BitsToOHE(const vector<Ciphertext<DCRTPoly>> ciphertext);

	vector<Ciphertext<DCRTPoly>> BitsToOHESIMD(const vector<Ciphertext<DCRTPoly>> ciphertext, const usint size);

}

#endif
