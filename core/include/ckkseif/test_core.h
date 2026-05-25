#ifndef CKKSEIF_TEST_CORE_H
#define CKKSEIF_TEST_CORE_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

	//----------------------------------------------------------------------------------
	//   Bootstrapping / utility benchmarks
	//----------------------------------------------------------------------------------

	void bootTest(const uint32_t scaleModSize, usint logbatchSize, usint levelBudgetElmt, usint iteration=2, usint precparam=10);
	void bootTest2();
	void logTest(const double bound, const usint degree, const usint iteration, const uint32_t scaleModSize=35);

	//----------------------------------------------------------------------------------
	//   EIF (EEF) benchmarks
	//----------------------------------------------------------------------------------

	void EEFTest(const usint bound, const usint iteration, const uint32_t scaleModSize=35);
	void EEFSIMDTest(const usint bound, const usint iteration, const uint32_t scaleModSize=35);
	void EEFTestDepth30(const usint bound, const usint iteration, const uint32_t scaleModSize=35);
	void EEFTests(const usint iteration, const uint32_t scaleModSize=35);
	void AnotherIndicatorTests(const usint iteration);
	void IndicatorBySincTest(const usint d, const usint K, const usint iteration, const uint32_t scaleModSize=35);

	void IndicatorByESFTest(const usint bound, const usint iteration, const uint32_t scaleModSize=35);
	void IndicatorByLagrangeTest(const usint bound, const usint iteration, const uint32_t scaleModSize=35);

	//----------------------------------------------------------------------------------
	//   Comparison / Encrypted Sign Function (ESF) benchmarks
	//   (used by both core and modules/privtopk; live in core because the primitive does)
	//----------------------------------------------------------------------------------

	void ESFTests(const uint32_t scaleModSize, const uint32_t bound);
	void ESFTest(const uint32_t scaleModSize, const uint32_t bound);
	void ESFQTest(const uint32_t scaleModSize, const uint32_t boundBits, const uint32_t baseBits);

}

#endif
