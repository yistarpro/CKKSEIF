#ifndef EIF_TESTCODE_H
#define EIF_TESTCODE_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {


	void bootTest(const uint32_t scaleModSize, usint logbatchSize, usint ringdim);

	void bootTest2();

	void binarybootTest(const uint32_t scaleModSize);


    string statTime(const vector<double> times, const usint iteration);

	void logTest(const double bound, const usint degree, const usint iteration, const uint32_t scaleModSize=35);


	void IndicatorTest(const usint bound, const usint iteration, const uint32_t scaleModSize=35);

	void IndicatorSIMDTest(const usint bound, const usint iteration, const uint32_t scaleModSize=35);

	void IndicatorTestDepth30(const usint bound, const usint iteration, const uint32_t scaleModSize=35);

 	void IndicatorTests(const usint iteration, const uint32_t scaleModSize=35);

	void AnotherIndicatorTests(const usint iteration);

	void dezTest(const usint d, const usint K, const usint iteration, const uint32_t scaleModSize=35);

	void ParityTest(const usint d, const usint K, const uint32_t scaleModSize);

	void RoundTest(const usint bound, const usint precis, const usint compprec,  const usint iteration, const uint32_t scaleModSize);


	void IndicatorByComparisonTest(const usint bound, const usint iteration, const uint32_t scaleModSize=35);
	
	void IndicatorByLagrangeTest(const usint bound, const usint iteration, const uint32_t scaleModSize=35);


	/////////////////////////////

 	void LUTLTTest(const usint bound, const usint outputdimension, const usint iteration);
 	
	void LUTCITest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);

 	void CodedLUTTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);

 	void CodedLUTSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);

 	void LUTSynthTests(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);

	/////////////////////////////

 	void EmbeddingTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);
 	
	void EmbeddingSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);

	void EmbeddingTests(const usint iteration);

	void EmbeddingSIMDTests(const usint iteration);



	// //----------------------------------------------------------------------------------
	// //   NLP TESTS
	// //----------------------------------------------------------------------------------
    
 	void LogregSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);

	void LogregSIMDTests(const usint iteration);

	void LogregTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);

	void LogregTests(const usint iteration);

	// //----------------------------------------------------------------------------------
	// //   Count TESTS
	// //----------------------------------------------------------------------------------
    
	void BDtest(const uint32_t scaleModSize, const uint32_t bound, const usint iter);

	void NaiveCountTest(const uint32_t scaleModSize, const uint32_t bound, usint size, const usint iteration);

	void CodedCountTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint exponentbound, const usint iteration);

	void CodedCountSIMDTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint maxlen, const usint iteration);

	void CountTest(const uint32_t scaleModSize, const uint32_t bound, const usint base);

	void CountSIMDTest(const uint32_t scaleModSize, const uint32_t bound, const usint base, const usint size);

	void NgramTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint exponentbound, const usint n, const double ratio, const usint iteration);

	void InfoRetrievalTest(const uint32_t scaleModSize, const uint32_t base, const usint dim, usint size, const usint vocabsize, const usint exponentbound, const usint iteration);

	void InfoRetrievalAfterTFTest(const uint32_t scaleModSize, usint size, const usint vocabsize, const usint iteration);



	// //----------------------------------------------------------------------------------
	// //   Sorting TESTS
	// //----------------------------------------------------------------------------------
    
	void ComparisonTests(const uint32_t scaleModSize, const uint32_t bound);

	void ComparisonTest(const uint32_t scaleModSize, const uint32_t bound);

	void rotTest();

	void SortTest(const uint32_t scaleModSize, const usint size, const int32_t arraybound);

	void SortFullTest(const uint32_t scaleModSize, const usint size, const int32_t arraybound);

	void kSorterTest(const uint32_t scaleModSize, const usint size, const int32_t arraybound, const usint k);

	void SortIterTest(const uint32_t scaleModSize, const usint size, const int32_t arraybound);

	void ptmodulusSwitchTest(const uint32_t scaleModSize);

	// static void compTest(long logp, long logq, long logSlots, long mod, long degf, long degg);

	// static void sortTest(long logp, long logSlots, long logsize);


}
#endif
