#ifndef EIF_TESTCODE_H
#define EIF_TESTCODE_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {


    void statTime(const vector<double> times, const usint iteration);

	void IndicatorTest(const usint bound, const usint iteration, const uint32_t scaleModSize=35);

	void IndicatorTestDepth30(const usint bound, const usint iteration, const uint32_t scaleModSize=35);

 	void IndicatorTests(const usint iteration, const uint32_t scaleModSize=35);

	void AnotherIndicatorTests(const usint iteration);

	void dezTest(const usint d, const usint K, const usint iteration, const uint32_t scaleModSize=35);

	void ParityTest(const usint d, const usint K, const uint32_t scaleModSize);

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


}
#endif
