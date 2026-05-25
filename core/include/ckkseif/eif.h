#ifndef CKKSEIF_EIF_H
#define CKKSEIF_EIF_H

#include "openfhe.h"
#include <iostream>
#include <map>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

	//----------------------------------------------------------------------------------
	//   Encrypted Indicator Function (EIF / EEF) — HELUT (ICML 2024) §3
	//   The proposed `EEF = Cleanse ∘ SqMethod` plus parameter selection.
	//----------------------------------------------------------------------------------

	vector<double> ParamSqMethod(const usint bound);

	Plaintext GenEEFChecker(const usint bound, const CryptoContext<DCRTPoly> cc);

	Plaintext GenEEFCheckerInterval(const usint from, const usint size, const CryptoContext<DCRTPoly> cc);

	//gen pt filled with: from ~ to-1
	Plaintext GenEEFCheckerIntervalRecursive(const usint from, const usint to, const usint size, const CryptoContext<DCRTPoly> cc);

	Plaintext GenEEFCheckerPartialArray(const usint from, const usint size, const CryptoContext<DCRTPoly> cc, const vector<usint> list);

	// Note: GenIndicatorCheckerForSIMDCOUNT moved to modules/hecount/include/ckkseif/hecount/counting.h —
	// it is hecount-specific (used only by CodedCountSIMD / ParalCount).

	// EEF rounds (r, s) for scaleModSize ∈ {35, 40, 45, 50, 55, 59}.
	vector<usint> ParamEEF(const usint bound, const usint scaleModSize);

	// ZeroTest rounds (r, s) for scaleModSize ∈ {35, 40, 45, 50, 59}.
	vector<usint> ParamZeroTest(const usint bound, const usint scaleModSize);


	Ciphertext<DCRTPoly> Cleanse(const Ciphertext<DCRTPoly> ciphertext, const usint round=1);

	Ciphertext<DCRTPoly> EEF(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const double numtocheck);

	// EEF specialization for p=2 (binary domain). For x ∈ {0, 1}: maps 0 → 1, 1 → 0.
	// Skips the SqMethod step and starts directly from `1 - x²`. Currently only
	// invoked by `EEFTestDepth30` for the binary corner case; no production caller.
	Ciphertext<DCRTPoly> EEFBinary(const Ciphertext<DCRTPoly> ciphertext, const vector<usint> rounds);

	// SIMD variant of EEF: `numtocheck` is broadcast per slot via a Plaintext mask.
	// `levlimit` triggers an in-loop EvalBootstrap once the ciphertext level exceeds it.
	Ciphertext<DCRTPoly> EEFSIMD(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds, const Plaintext numtocheck, const usint levlimit=100);

	// ZeroTest = EEF specialized to numtocheck=0 with one fewer initial squaring level.
	// Maps x=0 → 1 (hit), x ∈ (0, bound) → 0 (miss).
	Ciphertext<DCRTPoly> ZeroTest(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<usint> rounds);


	//----------------------------------------------------------------------------------
	//   EIF Alternatives (HELUT §D.3.1)
	//   Sinc-based and Lagrange-based indicators used as EEF baselines.
	//----------------------------------------------------------------------------------

	// Rotation-key utility shared by the embedding-style packing patterns used in
	// HELUT and HECount; lives here because consumers in multiple apps need it.
	void AddRotKeyForEmb(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t mk);

	// EEF by Sinc — alternative EIF from Lee et al. (HEaaN-Stat, 2023).
	Ciphertext<DCRTPoly> IndicatorBySinc(const Ciphertext<DCRTPoly> ciphertext, const usint d, const usint K);

	// EEF by Lagrange interpolation — HELUT §D.3.1 strawman.
	Ciphertext<DCRTPoly> IndicatorByLagrange(const Ciphertext<DCRTPoly> ciphertext, const usint bound, const vector<double> coeff);

}

#endif
