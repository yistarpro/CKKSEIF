#ifndef EIF_EMBEDDING_H
#define EIF_EMBEDDING_H

#include "openfhe.h"
#include "utils.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

class CompressedEmbedding {

public:
	long m=8;
	long k=8;
	long outputdimension=50;
	//path of index list
	string pathWtI="data/6B50d8_8wordtoindex.txt";
	//path of coded word embedding weight
	string pathWeight="data/6B50d8_8weight.txt";

	vector<double> weight;
	//map<string, vector<usint>> wordtoindex;

    CompressedEmbedding(const usint m=8, const usint k=8, const usint outputdimension=50);

};

}
#endif
