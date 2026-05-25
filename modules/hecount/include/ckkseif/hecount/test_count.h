#ifndef CKKSEIF_TEST_COUNT_H
#define CKKSEIF_TEST_COUNT_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

	//----------------------------------------------------------------------------------
	//   Counting benchmarks (NaiveCount, Count, CountEB, ParalCount)
	//----------------------------------------------------------------------------------

	void NaiveCountTest(const uint32_t scaleModSize, const uint32_t bound, usint size, const usint iteration);
	void CodedCountTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint exponentbound, const usint iteration);
	void CodedCountSIMDTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint maxlen, const usint iteration);

	//----------------------------------------------------------------------------------
	//   n-gram + Information Retrieval (TF-IDF pipeline) benchmarks
	//----------------------------------------------------------------------------------

	void NgramTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint exponentbound, const usint n, const double ratio, const usint iteration);
	void InfoRetrievalTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint vocabsize, const usint exponentbound, const usint iteration);
	void InfoRetrievalAfterTFTest(const uint32_t scaleModSize, usint size, const usint vocabsize, const usint iteration);

}

#endif
