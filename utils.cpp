#include "openfhe.h"
#include "utils.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkseif {

//----------------------------------------------------------------------------------
//   Copy & Repeat of Messages in Plaintext
//----------------------------------------------------------------------------------

vector<double> fullCopy(const vector<double> vals, const usint batchSize, const usint valsSize) {
	const usint copynum=batchSize/valsSize;
	usint base;
    vector<double> result(batchSize);

	for(usint i = 0; i < copynum; i++){
		base=i*valsSize;
		for(usint j=0 ; j < valsSize; j++){
			result[base+j]=vals[j];
		}
	}
    return result;
}

vector<double> repeat(const vector<double> vals, const usint batchSize, const usint repeatnum) {
	const usint valsSize=batchSize/repeatnum;
	usint base;
    vector<double> result(batchSize);

	for(usint i = 0; i < valsSize; i++){
		base=i*repeatnum;
		for(usint j=0 ; j < repeatnum; j++){
			result[base+j]=vals[i];
		}
	}
    return result;
}




// //----------------------------------------------------------------------------------	
// //   Read & Write
// //----------------------------------------------------------------------------------


vector<double> getWeight(const usint outputdimension, const usint mk, const string path) {
	ifstream fin;
	string line;
	usint base=0;
	vector<double> table(mk*outputdimension);
	fin.open(path, ios::in);
	if (fin.fail()){
		std::cerr << "Error!" << std::endl;
		return table;
	}

	while(getline(fin, line)){
		line.erase(line.find('['), 1);
		line.erase(line.find(']'), 1);

	    istringstream iss(line);       
    	string buffer;
		double num;

		long i=-1;
	    while (getline(iss, buffer, ',')) {
			if(i!=-1){
				buffer.erase(buffer.find('\''), 1);
				buffer.erase(buffer.find('\''), 1);
				num= std::stod(buffer);
        		table[base+i]=num;
			}
			i+=1;
    	}
		base+=outputdimension;
	}
	fin.close();
	return table;
}

// //----------------------------------------------------------------------------------
// //   Error Estimation
// //----------------------------------------------------------------------------------


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

vector<double> randomDiscreteArray(const usint size, const usint bound) {
	vector<double> result(size);
	for (usint i = 0; i < size; ++i) {
		result[i] = ((double)(rand()%bound))/((double)bound);
	}
	return result;
}

vector<double> fixedDiscreteArray(const usint size, const usint bound) {
	vector<double> result(size);
	for (usint i = 0; i < size; ++i) {
		result[i] = ((double)(i%bound))/((double)bound);
	}
	return result;
}

void paramcheck(const CryptoContext<DCRTPoly> cc){
    const auto cryptoParamsCKKS =
    std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
          cc->GetCryptoParameters());
    
    auto paramsQ = cc->GetElementParams()->GetParams();

    auto paramsQP = cryptoParamsCKKS->GetParamsQP();
    BigInteger P = BigInteger(1);
    for (uint32_t i = 0; i < paramsQP->GetParams().size(); i++) {
        if (i > paramsQ.size()) {
        P = P * BigInteger(paramsQP->GetParams()[i]->GetModulus());
        }
    }
    auto QBitLength = cc->GetModulus().GetLengthForBase(2);
    auto PBitLength = P.GetLengthForBase(2);
    std::cout << "\nQ = (bit length: " << QBitLength
                << ")" << std::endl;
    std::cout << "P = (bit length: " << PBitLength << ")"
                << std::endl;


}

void precision(const Plaintext vals, const vector<double> vals2, const usint size) {
	double max = 0;
	double tmp;
    vector<double> vals1 = vals->GetRealPackedValue();

	for (usint i = 0; i < size; ++i) {
		tmp = (vals1[i]-vals2[i]);
		if(tmp < 0)tmp= -tmp;
		if(tmp > max)max=tmp;
	}
	
    usint prec = -log2(max);

    cout << "Estimated precision in bits:" << prec << ", max error: " << max << endl;
}

usint precisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const usint interval) {
	double max = 0;
	double tmp;
    vector<double> vals1 = vals->GetRealPackedValue();

	for (usint i = 0; i < size; ++i) {
		tmp = (vals1[i*interval]-vals2[i]);
		if(tmp < 0)tmp= -tmp;
		if(tmp > max)max=tmp;
	}
	
    usint prec = -log2(max);

	return prec;
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
		tmp = (vals1[i]-vals2[i]);
		if(tmp < 0)tmp= -tmp;
		if(tmp > max)max=tmp;
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
		if(tmp2 < 0)tmp2= -tmp2;
		tmp = (tmp2-1.0);
		if(tmp < 0)tmp= -tmp;
		if(tmp > tmp2)tmp=tmp2;

		if(tmp > max)max=tmp;
	}
	
    usint prec = -log2(max);

    cout << "Estimated precision in bits:" << prec << ", max error: " << max << endl;
}

}
