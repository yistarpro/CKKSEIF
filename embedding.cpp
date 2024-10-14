#include "openfhe.h"
#include "utils.h"
#include "embedding.h"
#include <iostream>
#include <map>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {


CompressedEmbedding::CompressedEmbedding(const usint m, const usint k, const usint outputdimension): m(m), k(k), outputdimension(outputdimension) {
	string basicpath="../data/";
	if(outputdimension==50){
		pathWtI=basicpath+"6B50d"+to_string(m)+"_"+to_string(k)+"wordtoindex.txt";
		pathWeight=basicpath+"6B50d"+to_string(m)+"_"+to_string(k)+"weight.txt";
	}
	if(outputdimension==300){
		pathWtI=basicpath+"42B300d"+to_string(m)+"_"+to_string(k)+"wordtoindex.txt";
		pathWeight=basicpath+"42B300d"+to_string(m)+"_"+to_string(k)+"weight.txt";
	}
	if(outputdimension==768){
		pathWtI=basicpath+"gpt2768d"+to_string(m)+"_"+to_string(k)+"wordtoindex.txt";
		pathWeight=basicpath+"gpt2768d"+to_string(m)+"_"+to_string(k)+"weight.txt";
	}
	wordtoindex = getWordindex(m, pathWtI);
	weight=	getWeight(outputdimension, m*k, pathWeight);
    cout << "Embedding loaded: " << k << " x " << m << " coding with " << outputdimension << " output dimension" << endl;

}

LogregModel::LogregModel(const usint m, const usint k, const usint outputdimension): m(m), k(k), outputdimension(outputdimension) {
	string basicpath="../data/";
	if(outputdimension==50){
		pathWeight=basicpath+"6B50d"+to_string(m)+"_"+to_string(k)+"logreg.txt";
	}
	if(outputdimension==300){
		pathWeight=basicpath+"42B300d"+to_string(m)+"_"+to_string(k)+"logreg.txt";
	}
	if(outputdimension==768){
		pathWeight=basicpath+"gpt2768d"+to_string(m)+"_"+to_string(k)+"logreg.txt";
	}
	//wordtoindex = getWordindex(m, pathWtI);
	weight=	getWeightLogreg(outputdimension, pathWeight);
    cout << "Logreg Model loaded: " << k << " x " << m << " coding with " << outputdimension << " output dimension" << endl;

}


}
