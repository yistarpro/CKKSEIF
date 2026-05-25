
#ifndef EIF_UTILS_H
#define EIF_UTILS_H

#include "openfhe.h"
#include <iostream>
#include <map>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

    //----------------------------------------------------------------------------------
    //   SIMD slot-pattern helpers
    //----------------------------------------------------------------------------------

    // (a,b,c) → (a,b,c, a,b,c, a,b,c, ...) — copy `vals` to fill batchSize slots.
    vector<double> fullCopy(const vector<double> vals, const usint batchSize, const usint valsSize);

    // (a,b,c) → (a,a,a, b,b,b, c,c,c, ...) — repeat each entry `repeatnum` times.
    vector<double> repeat(const vector<double> vals, const usint batchSize, const usint repeatnum);

    //----------------------------------------------------------------------------------
    //   Embedding artifact loaders (used by helut / hecount)
    //----------------------------------------------------------------------------------

    vector<double> getWeight(const usint outputdimension, const usint mk, const string path = "data/6B50d8_8weight.txt");
    vector<double> getWeightLogreg(const usint outputdimension, const string path = "data/6B50d8_8weight.txt");

    map<string, vector<usint>> getWordindex(const usint m, const string path = "data/6B50d8_8wordtoindex.txt");
    map<usint, string>         getIndexToWord(const string path);

    //----------------------------------------------------------------------------------
    //   Text-data I/O (used by hecount IR pipeline)
    //----------------------------------------------------------------------------------

    vector<string> readsentence(const usint size, usint batchblocknum, usint batchblocksize, const string path = "../data/sentences.txt");
    vector<usint>  readlabels(usint batchblocknum, usint batchblocksize, const string path = "../data/sentences.txt");

    vector<double> readtexts(const usint size, const string filename, const double scale = 1, const double pad = 1023);
    void           writetext(const Plaintext inputtext, const usint size, const string filename, const double scale = 1);
    void           mapandwritetext(const Plaintext inputtext, const usint size, const string filename, const double scale = 1);

    //----------------------------------------------------------------------------------
    //   Debug print + library-side helpers
    //----------------------------------------------------------------------------------

    void printpt(const Plaintext pt, const usint length, usint linebreak = 0, const usint interval = 1, const bool rounding = true, const bool zerorounding = true, const int32_t mult_rounded = 0);

    // Used by modules/privtopk/src and several precision-check sites that
    // also exist outside test code.
    void  precision(const Plaintext vals, const vector<double> vals2, const usint size);

    // Boundary input generator used by privtopk's stress-test sweeps (library
    // side — not just tests).
    vector<double> fixedUBDiscreteArrayHalf(const usint size, const usint bound, const usint batchSize, const bool reversed = false);

}
#endif
