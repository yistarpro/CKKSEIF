#ifndef CKKSEIF_TEST_HELUT_H
#define CKKSEIF_TEST_HELUT_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

	//----------------------------------------------------------------------------------
	//   LUT benchmarks (HELUT-LT / HELUT-CI / CodedHELUT / CodedHELUT+p1)
	//----------------------------------------------------------------------------------

	void LUTLTTest(const usint bound, const usint outputdimension, const usint iteration);
	void LUTCITest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);
	void CodedLUTTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);
	void CodedLUTSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);
	void LUTSynthTests(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);

	//----------------------------------------------------------------------------------
	//   Encrypted embedding benchmarks
	//----------------------------------------------------------------------------------

	void EmbeddingTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);
	void EmbeddingSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);
	void EmbeddingTests(const usint iteration);
	void EmbeddingSIMDTests(const usint iteration);

	//----------------------------------------------------------------------------------
	//   Encrypted logistic-regression benchmarks (on top of CodedHELUT)
	//----------------------------------------------------------------------------------

	void LogregSIMDTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);
	void LogregSIMDTests(const usint iteration);
	void LogregTest(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);
	void LogregTestPlain(const usint bound, const usint numcode, const usint outputdimension, const usint iteration);
	void LogregTests(const usint iteration);
	void LogregTestsPlain(const usint iteration);

}

#endif
