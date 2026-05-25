#include "openfhe.h"
#include "utils.h"

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

//----------------------------------------------------------------------------
//   SIMD slot-pattern helpers
//----------------------------------------------------------------------------

// (a,b,c) → (a,b,c, a,b,c, …) — copy `vals` (size `valsSize`) across batchSize slots.
// Assumes `batchSize` is a multiple of `valsSize`; otherwise the trailing
// `batchSize % valsSize` slots are left zero-initialized.
vector<double> fullCopy(const vector<double> vals, const usint batchSize, const usint valsSize) {
    const usint copynum = batchSize / valsSize;
    vector<double> result(batchSize);

    for (usint i = 0; i < copynum; i++) {
        const usint base = i * valsSize;
        for (usint j = 0; j < valsSize; j++) {
            result[base + j] = vals[j];
        }
    }
    return result;
}

// (a,b,c) → (a,a,a, b,b,b, c,c,c, …) — repeat each entry of `vals` `repeatnum` times.
// `vals.size()` should equal `batchSize / repeatnum`.
vector<double> repeat(const vector<double> vals, const usint batchSize, const usint repeatnum) {
    const usint valsSize = batchSize / repeatnum;
    vector<double> result(batchSize);

    for (usint i = 0; i < valsSize; i++) {
        const usint base = i * repeatnum;
        for (usint j = 0; j < repeatnum; j++) {
            result[base + j] = vals[i];
        }
    }
    return result;
}

//----------------------------------------------------------------------------
//   Embedding artifact loaders
//----------------------------------------------------------------------------

vector<double> getWeight(const usint outputdimension, const usint mk, const string path) {
    ifstream fin;
    string line;
    usint base = 0;
    vector<double> table(mk * outputdimension);
    fin.open(path, ios::in);
    if (fin.fail()) {
        cerr << "Error!, " << path << endl;
        return table;
    }

    while (getline(fin, line)) {
        line.erase(line.find('['), 1);
        line.erase(line.find(']'), 1);

        istringstream iss(line);
        string buffer;
        double num;

        long i = -1;
        while (getline(iss, buffer, ',')) {
            if (i != -1) {
                buffer.erase(buffer.find('\''), 1);
                buffer.erase(buffer.find('\''), 1);
                num = stod(buffer);
                table[base + i] = num;
            }
            i += 1;
        }
        base += outputdimension;
    }
    fin.close();

    vector<double> transposed(mk * outputdimension);
    for (usint i = 0; i < outputdimension; i++) {
        for (usint j = 0; j < mk; j++) {
            transposed[i * mk + j] = table[j * outputdimension + i];
        }
    }
    return transposed;
}

vector<double> getWeightLogreg(const usint outputdimension, const string path) {
    ifstream fin;
    string line;
    vector<double> table(outputdimension + 1);
    fin.open(path, ios::in);
    if (fin.fail()) {
        cerr << "Error!, " << path << endl;
        return table;
    }

    while (getline(fin, line)) {
        line.erase(line.find('['), 1);
        line.erase(line.find(']'), 1);

        istringstream iss(line);
        string buffer;
        double num;

        long i = 0;
        while (getline(iss, buffer, ',')) {
            buffer.erase(buffer.find('\''), 1);
            buffer.erase(buffer.find('\''), 1);
            num = stod(buffer);
            table[i] = num;
            i += 1;
        }
    }
    fin.close();
    return table;
}

map<string, vector<usint>> getWordindex(usint m, string path) {
    ifstream fin;
    string line;
    string vec;
    map<string, vector<usint>> table;

    fin.open(path, ios::in);
    if (fin.fail()) {
        cerr << "Error!, " << path << endl;
        return table;
    }

    while (getline(fin, line)) {
        string tmpkey = line.substr(0, line.find(", ["));
        vec = line.substr(line.find(", [") + 3);
        vec.erase(vec.find(']'), 1);
        istringstream iss(vec);
        string buffer;
        double num;
        vector<usint> tmpvalue(m);

        usint i = 0;
        while (getline(iss, buffer, ',')) {
            buffer.erase(buffer.find('\''), 1);
            buffer.erase(buffer.find('\''), 1);
            num = stoi(buffer);
            tmpvalue[i] = num;
            i += 1;
        }
        table.insert(pair<string, vector<usint>>(tmpkey, tmpvalue));
    }
    fin.close();
    return table;
}

map<usint, string> getIndexToWord(string path) {
    ifstream fin;
    string line;
    string vec;
    map<usint, string> table;

    fin.open(path, ios::in);
    if (fin.fail()) {
        cerr << "Error!" << endl;
        return table;
    }

    while (getline(fin, line)) {
        istringstream iss(line);
        string buffer;
        usint tmpkey = 0;
        string tmpvalue = " ";

        usint i = 0;
        while (getline(iss, buffer, ',')) {
            if (i == 0) {
                tmpkey = stoi(buffer);
            } else {
                tmpvalue = buffer;
            }
            i += 1;
        }
        table.insert(pair<usint, string>(tmpkey, tmpvalue));
    }
    fin.close();
    return table;
}

//----------------------------------------------------------------------------
//   Text-data I/O (used by hecount IR pipeline)
//----------------------------------------------------------------------------

vector<string> readsentence(const usint size, usint batchblocknum, usint batchblocksize, const string path) {
    ifstream fin;
    string line;
    string vec;
    vector<string> result;

    fin.open(path, ios::in);
    if (fin.fail()) {
        cerr << "Error!, " << path << endl;
        return result;
    }

    usint j = 0;
    while (getline(fin, line)) {

        if (j >= batchblocknum * batchblocksize) {
            string tmpkey = line.substr(0, line.find(", ["));
            vec = line.substr(line.find(", [") + 3);
            vec.erase(vec.find(']'), 1);

            istringstream iss(vec);
            string buffer;
            usint i = 0;
            bool commacheck = false;
            string tmp;

            while (getline(iss, buffer, ',')) {
                if (commacheck == true) {
                    commacheck = false;
                    if (buffer.find('\'') < 1024) {
                        buffer.erase(buffer.find('\''), 1);
                    }
                    if (buffer.find('\"') < 1024) {
                        buffer.erase(buffer.find('\"'), 1);
                    }

                    tmp += ',' + buffer;
                    result.push_back(tmp);
                    i += 1;
                    if (i == size) break;

                } else {
                    if (buffer[0] == ' ') {
                        buffer.erase(0, 1);
                    }
                    if (buffer[0] == '\'') {
                        buffer.erase(buffer.find('\''), 1);
                    }
                    // FIXME: condition checks single-quote but erases double-quote;
                    // likely a typo from the pre-reorg code. Preserved to match the
                    // canonical Amazon-reviews dataset (state may be unreachable).
                    if (buffer[0] == '\'') {
                        buffer.erase(buffer.find('\"'), 1);
                    }

                    if (buffer.find('\'') < 1024) {
                        buffer.erase(buffer.find('\''), 1);
                        result.push_back(buffer);

                        i += 1;
                        if (i == size) break;
                    } else {
                        if (buffer.find('\"') < 1024) {
                            buffer.erase(buffer.find('\"'), 1);
                            result.push_back(buffer);
                            i += 1;
                            if (i == size) break;
                        } else {
                            commacheck = true;
                            tmp = buffer;
                        }
                    }
                }
            }
            while (i < size) {
                result.push_back("<pad>");
                i += 1;
            }
        }

        j++;

        if (j == batchblocknum * batchblocksize + batchblocksize) {
            break;
        }
    }
    fin.close();
    return result;
}

vector<usint> readlabels(usint batchblocknum, usint batchblocksize, const string path) {
    ifstream fin;
    string line;
    string vec;
    vector<usint> result;

    fin.open(path, ios::in);
    if (fin.fail()) {
        cerr << "Error!" << endl;
        return result;
    }

    usint j = 0;
    while (getline(fin, line)) {
        if (j >= batchblocknum * batchblocksize) {
            string tmpkey = line.substr(0, line.find(", ["));
            usint num = stoi(tmpkey);
            result.push_back(num);
        }
        j++;
        if (j == batchblocknum * batchblocksize + batchblocksize) break;
    }
    fin.close();
    return result;
}

vector<double> readtexts(const usint size, const string filename, const double scale, const double pad) {
    ifstream fin;
    string line;
    string vec;
    string path = "../data/" + filename;
    vector<double> result;

    fin.open(path, ios::in);
    if (fin.fail()) {
        cerr << "Error!" << endl;
        return result;
    }

    while (getline(fin, line)) {
        istringstream iss(line);
        string buffer;
        double num;
        usint i = 0;
        while (getline(iss, buffer, ',')) {
            num = stod(buffer);
            result.push_back(num / scale);
            i += 1;
            if (i == size) break;
        }
        while (i < size) {
            result.push_back(pad / scale);
            i += 1;
        }
    }
    fin.close();
    return result;
}

void writetext(const Plaintext inputtext, const usint size, const string filename, const double scale) {
    fstream fout;
    string path = "../data/" + filename;
    vector<double> plain = inputtext->GetRealPackedValue();

    fout.open(path, ios::out);
    if (fout.fail()) {
        cerr << "Error!" << endl;
    }

    for (usint i = 0; i < plain.size(); i++) {
        fout << plain[i] * scale;
        if ((i + 1) % size == 0) {
            fout << endl;
        } else {
            fout << ", ";
        }
    }
    fout.close();
}

void mapandwritetext(const Plaintext inputtext, const usint size, const string filename, const double scale) {
    fstream fout;
    string idxpath = "../data/idxtoword_amazon.txt";
    string path    = "../data/" + filename;
    map<usint, string> idxset = getIndexToWord(idxpath);
    vector<double> plain = inputtext->GetRealPackedValue();

    fout.open(path, ios::out);
    if (fout.fail()) {
        cerr << "Error!" << endl;
    }

    for (usint i = 0; i < plain.size(); i++) {
        usint idxtmp = (int)(plain[i] * scale + 0.5);
        if (idxtmp < idxset.size()) fout << idxset[idxtmp];
        if ((i + 1) % size == 0) {
            fout << endl;
        } else {
            if (idxtmp < idxset.size()) fout << ", ";
        }
    }
    fout.close();
}

//----------------------------------------------------------------------------
//   Debug print + library-side helpers
//----------------------------------------------------------------------------

void printpt(const Plaintext pt, const usint length, usint linebreak, const usint interval, const bool rounding, const bool zerorounding, const int32_t mult_rounded) {
    if (linebreak == 0) linebreak = length;
    vector<double> vals1 = pt->GetRealPackedValue();
    bool printed = false;

    if ((mult_rounded > 1) && (printed == false)) {
        printed = true;
        for (usint i = 0; i < length; i++) {
            if (i % linebreak == 0) cout << endl;
            cout << round(vals1[interval * i] * (double) mult_rounded) << ", ";
        }
        cout << endl;
    }

    if (zerorounding && (printed == false)) {
        printed = true;
        for (usint i = 0; i < length; i++) {
            if (i % linebreak == 0) cout << endl;
            if (vals1[interval * i] < 0.0001) {
                cout << 0 << ", ";
            } else {
                cout << vals1[interval * i] << ", ";
            }
        }
        cout << endl;
    }

    if (rounding && (printed == false)) {
        printed = true;
        for (usint i = 0; i < length; i++) {
            if (i % linebreak == 0) cout << endl;
            cout << round(vals1[interval * i]) << ", ";
        }
        cout << endl;
    }
}

// Compute max absolute error between decrypted plaintext and reference vector,
// print precision (in bits) = -log2(max error). Used as a diagnostic from both
// library code (privtopk/parity) and benchmark tests.
//
// When max error is 0 (exact match), reports "exact" instead of -log2(0) → +inf
// which would UB on cast to usint.
void precision(const Plaintext vals, const vector<double> vals2, const usint size) {
    vector<double> vals1 = vals->GetRealPackedValue();
    double maxErr = 0;
    for (usint i = 0; i < size; ++i) {
        double diff = vals1[i] - vals2[i];
        if (diff < 0)     diff   = -diff;
        if (diff > maxErr) maxErr = diff;
    }

    if (maxErr == 0) {
        cout << "Estimated precision in bits: exact (max error = 0)" << endl;
    } else {
        const usint prec = static_cast<usint>(-log2(maxErr));
        cout << "Estimated precision in bits: " << prec
             << ", max error: " << maxErr << endl;
    }
}

vector<double> fixedUBDiscreteArrayHalf(const usint size, const usint bound, const usint batchSize, const bool reversed) {
    usint arraysize = batchSize;
    if (size > batchSize) arraysize = size;
    vector<double> result(arraysize);
    usint c       = bound - 1;
    usint counter = 0;
    const usint minimum = 1;

    cout << "size: " << size << ", bound: " << bound << endl;

    if (reversed) {
        for (usint i = 0; i < size / 2; ++i) {
            result[arraysize - 2 * i - 1] = ((double) c) / ((double) bound * 2.0);
            counter += 1;
            if (counter + c == bound) {
                counter = 0;
                if (c > minimum) c -= 1;
            }
        }
    } else {
        for (usint i = 0; i < size / 2; ++i) {
            result[2 * i] = ((double) c) / ((double) bound * 2.0);
            counter += 1;
            if (counter + c == bound) {
                counter = 0;
                if (c > minimum) c -= 1;
            }
        }
    }
    return result;
}

}
