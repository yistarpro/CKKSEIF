#ifndef CKKSEIF_PARITY_TEST_PARITY_H
#define CKKSEIF_PARITY_TEST_PARITY_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

	//----------------------------------------------------------------------------------
	//   Parity playground benchmarks. Restored from the pre-reorg `testcode.cpp`
	//   (where they were commented out). Not associated with any paper section yet
	//   — feel free to extend.
	//----------------------------------------------------------------------------------

	// Test ParityBySin (depth-d / Chebyshev-order-K parity primitive).
	void ParityTest(const usint d, const usint K, const uint32_t scaleModSize);

	// Bit-Decomposition test — exercises ExtractLSBs / ExtractMSBs / DecompToBits.
	void BDtest(const uint32_t scaleModSize, const uint32_t bound, const usint iter);

}

#endif
