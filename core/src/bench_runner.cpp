#include "openfhe.h"
#include "bench_runner.h"

#include <fstream>
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

//----------------------------------------------------------------------------
//   Synthetic input generators
//----------------------------------------------------------------------------

vector<double> randomRealArray(const usint size, const double bound) {
    vector<double> result(size);
    for (usint i = 0; i < size; ++i) {
        result[i] = (double) rand()/(RAND_MAX) * bound;
    }
    return result;
}

vector<double> randomIntArray(const usint size, const usint bound) {
    vector<double> result(size);
    for (usint i = 0; i < size; ++i) {
        result[i] = (double) (rand()%bound);
    }
    return result;
}

vector<usint> fixedIntArray(const usint size, const usint bound) {
    vector<usint> result(size);
    usint loga = (usint)log2(size);
    usint base = pow(2, loga/2);
    usint pointer = 0;
    for (usint i = 0; i < base; ++i) {
        for (usint j = 0; j < i+1; j++) {
            result[pointer] = i % bound;
            pointer += 1;
        }
    }
    return result;
}

vector<double> randomIntArrayNoised(const usint size, const usint bound, const usint noiselevel) {
    vector<double> result(size);
    for (usint i = 0; i < size; ++i) {
        result[i] = (double) (rand()%bound);
        result[i] += ((double)(rand()%1000)) * (1 / (1000 * ((double)(1 << noiselevel))));
    }
    return result;
}

vector<double> randomForRound(const usint size, const usint bound, const usint precision) {
    vector<double> result(size);
    for (usint i = 0; i < size; ++i) {
        result[i]  = (double) (rand() % (bound - 1));
        result[i] += ((double)(rand() % precision)) / ((double) precision);
        result[i] += 0.5 / ((double) precision);
    }
    return result;
}

vector<double> randomDiscreteArray(const usint size, const usint bound) {
    vector<double> result(size);
    for (usint i = 0; i < size; ++i) {
        result[i] = ((double)(rand() % bound)) / ((double) bound);
    }
    return result;
}

vector<double> fixedDiscreteArray(const usint size, const usint bound) {
    vector<double> result(size);
    for (usint i = 0; i < size; ++i) {
        result[i] = ((double)(i % bound)) / ((double) bound);
    }
    return result;
}

vector<double> randomDiscreteArrayHalf(const usint size, const usint bound) {
    vector<double> result(size);
    for (usint i = 0; i < size; ++i) {
        result[i] = ((double)(rand() % bound)) / ((double) bound * 2.0);
    }
    return result;
}

vector<double> fixedDiscreteArrayHalf(const usint size, const usint bound) {
    vector<double> result(size);
    for (usint i = 0; i < size; ++i) {
        result[i] = ((double)(i % bound)) / ((double) bound * 2.0);
    }
    return result;
}

vector<double> fixedUBDiscreteArray(const usint size, const usint bound, const usint batchSize) {
    usint arraysize = batchSize;
    if (size > batchSize) arraysize = size;
    vector<double> result(arraysize);
    usint c       = bound - 1;
    usint counter = 0;
    const usint minimum = 1;

    cout << "size: " << size << ", bound: " << bound << endl;

    for (usint i = 0; i < size / 2; ++i) {
        result[2 * i] = ((double) c) / ((double) bound);
        counter += 1;
        if (counter + c == bound) {
            counter = 0;
            if (c > minimum) c -= 1;
        }
    }
    return result;
}

vector<double> equalvalueArray(const usint size, const usint bound, const usint batchSize) {
    usint arraysize = batchSize;
    if (size > batchSize) arraysize = size;
    vector<double> result(arraysize);

    cout << "size: " << size << ", bound: " << bound << endl;

    for (usint i = 0; i < size / 2; ++i) {
        result[2 * i] = ((double)(bound - 1)) / ((double)(2 * bound));
    }
    return result;
}

//----------------------------------------------------------------------------
//   CKKS parameter / bootstrap diagnostics
//----------------------------------------------------------------------------

void paramcheck(const CryptoContext<DCRTPoly> cc) {
    const auto cryptoParamsCKKS =
        dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    auto paramsQ  = cc->GetElementParams()->GetParams();
    auto paramsQP = cryptoParamsCKKS->GetParamsQP();

    BigInteger P = BigInteger(1);
    for (uint32_t i = 0; i < paramsQP->GetParams().size(); i++) {
        if (i > paramsQ.size()) {
            P = P * BigInteger(paramsQP->GetParams()[i]->GetModulus());
        }
    }

    auto RingDim    = log2(cc->GetRingDimension());
    auto QBitLength = cc->GetModulus().GetLengthForBase(2);
    auto PBitLength = P.GetLengthForBase(2);

    cout << "\nQ = (bit length: " << QBitLength << ")" << endl;
    cout << "P = (bit length: "   << PBitLength << ")" << endl;
    cout << "RingDim = (bit length: " << RingDim << ")" << endl;
}

void bootSet1(CCParams<CryptoContextCKKSRNS> parameters, const usint scaleModSize) {
    parameters.SetFirstModSize(scaleModSize + 1);
    parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);
    parameters.SetSecretKeyDist(SPARSE_TERNARY);
    parameters.SetNumLargeDigits(0);
    parameters.SetKeySwitchTechnique(HYBRID);
}

void bootSet2(CryptoContext<DCRTPoly> cc, const PrivateKey<DCRTPoly> privateKey, const usint batchSize) {
    cc->Enable(FHE);

    usint RingDim         = log2(cc->GetRingDimension());
    usint levelBudgetElmt = (RingDim > 15) ? 1u << (RingDim - 14) : 2u;

    vector<uint32_t> levelBudget = {levelBudgetElmt, levelBudgetElmt};
    cout << "level budget: " << levelBudgetElmt << endl;
    cc->EvalBootstrapSetup(levelBudget, {0, 0}, batchSize);

    const auto cryptoParamsCKKS =
        dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    usint depth = FHECKKSRNS::GetBootstrapDepth(levelBudget, cryptoParamsCKKS->GetSecretKeyDist());
    cout << "BootDepth: " << depth << endl;

    cc->EvalBootstrapKeyGen(privateKey, batchSize);
    cout << "Boot Keygen Done" << endl;
}

//----------------------------------------------------------------------------
//   Timing-stat formatter
//----------------------------------------------------------------------------

string statTime(const vector<double> times, const usint iteration) {
    if (iteration == 1) {
        cout << "Average time = " << times[0] << endl;
        return "Average time = " + to_string(times[0]);
    }
    double avg = 0.0;
    double std = 0.0;
    for (usint j = 0; j < iteration; j++) avg += times[j];
    avg /= iteration;
    for (usint j = 0; j < iteration; j++) std += (times[j] - avg) * (times[j] - avg);
    std = sqrt(std / iteration);
    cout << "Average time = " << avg << ", Std =" << std << endl;
    return "Average time = " + to_string(avg) + ", Std =" + to_string(std);
}

//----------------------------------------------------------------------------
//   Precision / accuracy diagnostics
//----------------------------------------------------------------------------

usint precisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const usint interval) {
    double max = 0;
    double tmp;
    vector<double> vals1 = vals->GetRealPackedValue();

    for (usint i = 0; i < size; ++i) {
        tmp = (vals1[i * interval] - vals2[i]);
        if (tmp < 0)   tmp  = -tmp;
        if (tmp > max) max  = tmp;
    }

    return (usint) -log2(max);
}

void compprecision(const Ciphertext<DCRTPoly> ciphertext, const vector<double> vals2, const usint size, const CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly> keys) {
    double max = 0;
    double tmp;
    Plaintext result;
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(vals2);
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    c1 = cc->EvalMult(c1, ciphertext);
    cc->ModReduceInPlace(c1);
    cc->Decrypt(keys.secretKey, c1, &result);

    vector<double> vals1 = result->GetRealPackedValue();
    for (usint i = 0; i < size; ++i) {
        tmp = (vals1[i] - vals2[i]);
        if (tmp < 0)   tmp = -tmp;
        if (tmp > max) max = tmp;
    }

    usint prec = -log2(max);
    cout << "Estimated precision in bits(Comparison measure):" << prec << ", max error: " << max << endl;
}

void binaryprecision(const Plaintext vals, const usint size) {
    double max = 0;
    double tmp;
    double tmp2;
    vector<double> vals1 = vals->GetRealPackedValue();

    for (usint i = 0; i < size; ++i) {
        tmp2 = vals1[i];
        if (tmp2 < 0)    tmp2 = -tmp2;
        tmp  = (tmp2 - 1.0);
        if (tmp < 0)     tmp  = -tmp;
        if (tmp > tmp2)  tmp  = tmp2;
        if (tmp > max)   max  = tmp;
    }

    usint prec = -log2(max);
    cout << "Estimated precision in bits:" << prec << ", max error: " << max << endl;
}

double countprecisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const bool show) {
    double tmp = 0;
    vector<double> vals1 = vals->GetRealPackedValue();
    double prec = 100;

    for (usint i = 0; i < size; ++i) {
        if (vals2[i] == resultnum) tmp += 1;
    }
    if (show) cout << "True: " << tmp << ", Estimated: " << vals1[0] << endl;
    tmp = (vals1[0] - tmp);
    if (tmp < 0) tmp = -tmp;
    if (prec > -log2(tmp)) prec = -log2(tmp);
    return prec;
}

double countSIMDprecisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const bool show) {
    double tmp = 0;
    vector<double> vals1 = vals->GetRealPackedValue();
    usint num = vals1.size() / size;
    double prec = 100;

    for (usint j = 0; j < num; j++) {
        for (usint i = 0; i < size; ++i) {
            if (vals2[i] == num * resultnum + j) tmp += 1;
        }
        if (show) cout << "True: " << tmp << ", Estimated: " << vals1[j * size] << endl;
        tmp = (vals1[j * size] - tmp);
        if (tmp < 0) tmp = -tmp;
        if (prec > -log2(tmp)) prec = -log2(tmp);
    }
    return prec;
}

double codedcountprecisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const bool show) {
    double tmp = 0;
    vector<double> vals1 = vals->GetRealPackedValue();
    double prec = 100;

    for (usint i = 0; i < size; ++i) {
        if (vals2[i] == resultnum) tmp += 1;
    }
    if (show) cout << "True: " << tmp << ", Estimated: " << vals1[0] << endl;
    tmp = (vals1[0] - tmp);
    if (tmp < 0) tmp = -tmp;
    if (prec > -log2(tmp)) prec = -log2(tmp);
    return prec;
}

void roundprecision(const vector<double> vals1, const vector<double> vals2, const usint size) {
    double tmp;
    usint count = 0;
    for (usint i = 0; i < size; ++i) {
        tmp = round(vals1[i]) - round(vals2[i]);
        if (((int) tmp) % 2 == 0) count++;
    }
    cout << "accurate num:" << count << ", accuracy: " << (double) count / (double) size << endl;
}

//----------------------------------------------------------------------------
//   Result-logging helpers
//----------------------------------------------------------------------------

usint checkline(const string path) {
    ifstream fin;
    string line;
    fin.open(path, ios::in);
    if (fin.fail()) {
        cout << "empty" << endl;
        return 0;
    }

    usint count = 0;
    while (getline(fin, line)) {
        count += 1;
    }
    fin.close();
    cout << count << endl;
    return count;
}

void addRes(vector<string> newline, string path, usint iteration) {
    fstream fout;
    fout.open(path, ios::out | ios::app);
    if (fout.fail()) {
        cerr << "Error!" << endl;
    }
    for (usint i = 0; i < iteration + 2; i++) {
        fout << newline[i] << endl;
    }
    fout.close();
}

}
