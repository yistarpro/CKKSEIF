#include "openfhe.h"
#include "test_parity.h"
#include "test_core.h"
#include "parity.h"
#include "algorithms.h"  // umbrella → eif.h + arithmetic.h (Cleanse, RotSum)
#include "utils.h"
#include "bench_runner.h"

#include <omp.h>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

	// Parity playground — ParityBySin (depth-d / Chebyshev-order-K parity primitive).
	// Single-shot smoke test, not paper-attributed. Inputs drawn from [0, 2^d).
	void ParityTest(const usint d, const usint K, const uint32_t scaleModSize) {

		//─── 1. Parameters ──────────────────────────────────────────────────
		TimeVar         t;
		const uint32_t  batchSize = 1u << 16;
		const uint32_t  multDepth = 25;
		const usint     bound     = 1u << d;

		printBenchHeader("ParityTest", {
			{"bound",     to_string(bound)},
			{"d",         to_string(d)},
			{"K",         to_string(K)},
			{"scaleMod",  to_string(scaleModSize)},
			{"multDepth", to_string(multDepth)},
		});

		//─── 2. CKKS context + keys ─────────────────────────────────────────
		auto ctx  = makeCKKSContext(multDepth, scaleModSize, batchSize,
		                            {CKKSFeature::PKE, CKKSFeature::KEYSWITCH,
		                             CKKSFeature::LEVELEDSHE, CKKSFeature::ADVANCEDSHE});
		auto cc   = ctx.cc;
		auto keys = ctx.keys;

		//─── 3. Inputs ──────────────────────────────────────────────────────
		vector<double>        inputVec = randomIntArray(batchSize, bound);
		inputVec[0] = 0.0;
		Plaintext             inputPt  = cc->MakeCKKSPackedPlaintext(inputVec);
		Ciphertext<DCRTPoly>  inputCt  = cc->Encrypt(keys.publicKey, inputPt);

		//─── 4. Timed evaluation (single-shot) ──────────────────────────────
		TIC(t);
		Ciphertext<DCRTPoly>  resultCt = ParityBySin(inputCt, d, K);
		double                timeEval = TOC(t);

		//─── 5. Validation ──────────────────────────────────────────────────
		Plaintext resultPt;
		cc->Decrypt(keys.secretKey, resultCt, &resultPt);
		binaryprecision(resultPt, batchSize);
		resultPt->SetLength(8);
		cout.precision(8);
		cout << "result=" << resultPt
		     << ", level=" << resultPt->GetLevel()
		     << ", time=" << timeEval << " ms" << endl;
	}

	// Parity playground — Bit-decomposition smoke test for ExtractLSBs.
	// Configured for a bootstrap-capable context (FLEXIBLEAUTOEXT + SPARSE_TERNARY
	// + bootSet2) so the swap-in alternatives `ExtractMSBs` / `DecompToBits`
	// (commented in the eval section) can be tried without re-tuning params.
	//
	// Note: the `iter` argument is *not* a per-call iteration count — it's a
	// pass-through bit-count parameter that the alternative `ExtractMSBs(c1,
	// bound, iter)` swap consumes. The default `ExtractLSBs(c1, bound,
	// log2(bound))` path ignores it.
	void BDtest(const uint32_t scaleModSize, const uint32_t bound, const usint iter) {

		//─── 1. Parameters ──────────────────────────────────────────────────
		TimeVar         t;
		const uint32_t  batchSize = 1u << 16;
		const uint32_t  multDepth = 2320 / scaleModSize;

		printBenchHeader("BDtest", {
			{"bound",     to_string(bound)},
			{"iter",      to_string(iter)},     // pass-through to ExtractMSBs alt
			{"scaleMod",  to_string(scaleModSize)},
			{"multDepth", to_string(multDepth)},
		});

		//─── 2. CKKS context + keys (with bootstrap setup) ──────────────────
		CCParams<CryptoContextCKKSRNS> parameters;
		parameters.SetMultiplicativeDepth(multDepth);
		parameters.SetScalingModSize(scaleModSize);
		parameters.SetRingDim(batchSize << 1);
		parameters.SetBatchSize(batchSize);
		parameters.SetFirstModSize(scaleModSize + 1);
		parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);
		parameters.SetSecretKeyDist(SPARSE_TERNARY);
		parameters.SetNumLargeDigits(0);
		parameters.SetKeySwitchTechnique(HYBRID);

		CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
		cc->Enable(PKE);
		cc->Enable(KEYSWITCH);
		cc->Enable(LEVELEDSHE);
		cc->Enable(ADVANCEDSHE);
		paramcheck(cc);

		KeyPair<DCRTPoly> keys = cc->KeyGen();
		cc->EvalMultKeyGen(keys.secretKey);
		TIC(t);
		bootSet2(cc, keys.secretKey, batchSize);
		cout << "bootSet2 time: " << TOC(t) << " ms" << endl;

		//─── 3. Inputs ──────────────────────────────────────────────────────
		vector<double>        inputVec = randomIntArray(batchSize, bound);
		Plaintext             inputPt  = cc->MakeCKKSPackedPlaintext(inputVec);
		Ciphertext<DCRTPoly>  inputCt  = cc->Encrypt(keys.publicKey, inputPt);

		//─── 4. Timed evaluation (single-shot) ──────────────────────────────
		// Default: extract the low log2(bound) bits via ExtractLSBs.
		// Swap with `ExtractMSBs(inputCt, bound, iter)` or
		// `DecompToBits(inputCt, log2(bound), multDepth)` to test those.
		TIC(t);
		vector<Ciphertext<DCRTPoly>> bitCts = ExtractLSBs(inputCt, bound, log2(bound));
		double                       timeEval = TOC(t);

		//─── 5. Per-bit validation ──────────────────────────────────────────
		Plaintext resultPt;
		for (usint b = 0; b < bitCts.size(); b++) {
			cc->Decrypt(keys.secretKey, bitCts[b], &resultPt);
			binaryprecision(resultPt, batchSize);
			resultPt->SetLength(16);
			cout << "  bit " << b << ": " << resultPt
			     << ", level=" << resultPt->GetLevel() << endl;
		}
		cout << "Total time: " << timeEval << " ms" << endl;
	}

} // namespace ckkseif
