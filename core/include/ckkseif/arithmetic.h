#ifndef CKKSEIF_ARITHMETIC_H
#define CKKSEIF_ARITHMETIC_H

#include "openfhe.h"
#include <iostream>
#include <map>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

	//----------------------------------------------------------------------------------
	//   Rotation index helpers and Po2 rotation keys
	//----------------------------------------------------------------------------------

	std::vector<int32_t> GenIdxForRotsum(const int32_t from, const int32_t to, const bool bidirectional = false);

	std::vector<int32_t> GenIdxForMultiples(const int32_t base, const int32_t number, const bool bidirectional = false);

	void AddRotKeyForPo2(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t batchSize);

	//----------------------------------------------------------------------------------
	//   Advanced Homomorphic Operations
	//----------------------------------------------------------------------------------

	Ciphertext<DCRTPoly> BootAuto(const Ciphertext<DCRTPoly> ciphertext);

	Ciphertext<DCRTPoly> Product(const vector<Ciphertext<DCRTPoly>> ciphertext);

	Ciphertext<DCRTPoly> EvalLog(const Ciphertext<DCRTPoly> ciphertext, const double bound, const double base, const usint degree);

	Ciphertext<DCRTPoly> EvalLogLike(const Ciphertext<DCRTPoly> ciphertext, const double bound);

	Ciphertext<DCRTPoly> EvalInverse(const Ciphertext<DCRTPoly> ciphertext, const double bound, const usint degree);

	// Rotation-and-sum primitive (HECount §2.2, PrivTopk §II-C).
	Ciphertext<DCRTPoly> RotSum(const Ciphertext<DCRTPoly> ciphertext, const int32_t from, const int32_t to, const bool verbose = false);
	//16 to 1 : sum up 16 slots
	//Col Sum: RotSum(ciphertext, size, 1);
	//Row Sum: RotSum(ciphertext, sizesquare, size);
	//Transpose Row to Col: RotSum(ciphertext, -(sizesquare-size), -(size-1));
	//Transpose Col to Row: RotSum(ciphertext, sizesquare-size, size-1);
	//Copy Col: RotSum(ciphertext, -size, -1);
	//Copy Row: RotSum(ciphertext, -sizesquare, -size);
	//fullCopy: RotSum(ciphertext, -batchSize, -size);

	//----------------------------------------------------------------------------------
	//   Encrypted Sign Function (ESF)
	//   Origin: Cheon, Kim, Kim — "Numerical Method for Comparison on Homomorphically
	//   Encrypted Numbers", Asiacrypt 2019 (CKK19).
	//   Two-tier API: `EncryptedSignFunction` is the fully parametric form
	//   (caller passes polynomial degrees); `ESF` is the convenience wrapper
	//   that auto-selects degrees from `bound`. `ESFQ` / `ESFQReconstruct`
	//   are the quantized (high-precision) variants used by PrivTopk §V-B2.
	//----------------------------------------------------------------------------------

	Ciphertext<DCRTPoly> Normalize(const Ciphertext<DCRTPoly> ciphertext, const double bound);

	// customizable EncryptedSignFunction (full parametric form)
	Ciphertext<DCRTPoly> EncryptedSignFunction(const Ciphertext<DCRTPoly> ciphertext, const usint degf, const usint degg, const double bound, const usint ver);

	// optimized EncryptedSignFunction (convenience wrapper)
	Ciphertext<DCRTPoly> ESF(const Ciphertext<DCRTPoly> ciphertext, const double bound=1.0, const bool lastmod=false, const usint levlimit=100);
	Ciphertext<DCRTPoly> ESFQ(const vector<Ciphertext<DCRTPoly>> ciphertext, const double bound=1.0, const bool lastmod=false, const usint levlimit=100);
	Ciphertext<DCRTPoly> ESFQReconstruct(const vector<Ciphertext<DCRTPoly>> ciphertext, const bool lastmod=false);

	//----------------------------------------------------------------------------------
	//   Debug / testing helpers
	//----------------------------------------------------------------------------------

	//Recrypt by decrypt-encrypt. Used for tests.
	Ciphertext<DCRTPoly> FakeBoot(const Ciphertext<DCRTPoly> ciphertext, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys, bool verbose = true);
	void CheckDecrypted(const Ciphertext<DCRTPoly> ciphertext, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys);

}

#endif
