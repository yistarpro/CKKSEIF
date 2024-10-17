#include "openfhe.h"
#include "utils.h"
#include <iostream>
#include <map>

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

// complex<double>* UTILS::padcomplex(complex<double>* vals, usint current, usint batchSize) {
// 	complex<double>* res=new complex<double>[batchSize];
// 	if(current==batchSize){
// 		return vals;
// 	}

// 	for(usint i=0; i<current; i++){
// 		res[i]=vals[i];
// 	}
// 	for(usint i=current; i<batchSize; i++){
// 		res[i]=0.0;
// 	}
// 	return res;

// }


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
		std::cerr << "Error!, " << path << std::endl;
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

	vector<double> transposed(mk*outputdimension);
	for(usint i=0; i<outputdimension;i++){
		for(usint j=0; j<mk;j++){
			transposed[i*mk+j] = table[j*outputdimension+i];
		}
	}

	return transposed;
}


vector<double> getWeightLogreg(const usint outputdimension, const string path) {
	ifstream fin;
	string line;
	vector<double> table(outputdimension+1);
	fin.open(path, ios::in);
	if (fin.fail()){
		std::cerr << "Error!, " << path <<  std::endl;
		return table;
	}

	while(getline(fin, line)){
		line.erase(line.find('['), 1);
		line.erase(line.find(']'), 1);

	    istringstream iss(line);       
    	string buffer;
		double num;

		long i=0;
	    while (getline(iss, buffer, ',')) {
			buffer.erase(buffer.find('\''), 1);
			buffer.erase(buffer.find('\''), 1);
			num= std::stod(buffer);
			table[i]=num;
			i+=1;
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
	if (fin.fail()){
		std::cerr << "Error!, " << path << std::endl;
		return table;
	}
	

	while(getline(fin, line)){
		string tmpkey=line.substr(0, line.find(", ["));
		vec=line.substr(line.find(", [")+3);
		vec.erase(vec.find(']'), 1);
	    istringstream iss(vec);       
    	string buffer;
		double num;
		vector<usint> tmpvalue(m);

		usint i=0;
	    while (getline(iss, buffer, ',')) {
			buffer.erase(buffer.find('\''), 1);
			buffer.erase(buffer.find('\''), 1);
			num= std::stoi(buffer);
        	tmpvalue[i]=num;
			i+=1;
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
	if (fin.fail()){
		std::cerr << "Error!" << std::endl;
		return table;
	}
	

	while(getline(fin, line)){
	    istringstream iss(line);       
    	string buffer;
		usint tmpkey=0;
		string tmpvalue=" ";

		usint i=0;
	    while (getline(iss, buffer, ',')) {
			if(i==0){
				tmpkey=std::stoi(buffer);
			}else{
				tmpvalue=buffer;
			}
			i+=1;
    	}
		table.insert(pair<usint, string>(tmpkey, tmpvalue));
	}
	fin.close();
	return table;
}

// map<string, complex<double>*> SerializationUtils::getEmb(usint numfeature) {
// 	string path ="../data/"+to_string(numfeature)+"indextoemb.txt";
// 	ifstream fin;
// 	string line;
// 	string vec;
// 	map<string, complex<double>*> table;

// 	fin.open(path, ios::in);
// 	if (fin.fail()){
// 		std::cerr << "Error!" << std::endl;
// 		return table;
// 	}
	

// 	while(getline(fin, line)){
// 		string tmpkey=line.substr(0, line.find(", ["));
// 		vec=line.substr(line.find(", [")+3);
// 		vec.erase(vec.find(']'), 1);
// 	    istringstream iss(vec);       
//     	string buffer;
// 		double num;
// 		complex<double>* tmpvalue=new complex<double>[numfeature];

// 		usint i=0;
// 	    while (getline(iss, buffer, ',')) {
// 			buffer.erase(buffer.find('\''), 1);
// 			buffer.erase(buffer.find('\''), 1);
// 			num= std::stod(buffer);
//         	tmpvalue[i]=num;
// 			i+=1;
//     	}
// 		table.insert(pair<string, complex<double>*>(tmpkey, tmpvalue));
// 	}
// 	fin.close();
// 	return table;
// }

// void SerializationUtils::writePt(string* plain, complex<double>* result, usint n, usint vectorsize, usint m, usint k,usint repeatnum, usint numfeature){
// 	fstream fout;
// 	usint mk=m*k;
// 	string path="../data/"+to_string(numfeature)+"_"+to_string(m)+"_"+to_string(k)+"_"+to_string(repeatnum)+"_result.txt";

// 	fout.open(path, ios::out);
// 	if (fout.fail())
// 		{
// 			std::cerr << "Error!" << std::endl;
// 		}
// 	usint base=0;
// 	for(usint i=0; i<(n/(mk*repeatnum)); i++){
// 		base=i*mk*repeatnum;
// 		fout << plain[i];
// 		for(usint j=0; j<vectorsize; j++){
// 			fout <<  ", " << result[base+j].real();
// 		}
// 		if(i!=(n/(mk*repeatnum))-1)fout << endl;
// 	}
// 	fout.close();
// }

// void SerializationUtils::addPt(complex<double>* result, usint n, usint vectorsize, usint m, usint k,usint repeatnum, usint numfeature){
// 	ifstream fin;
// 	fstream fout;
// 	string line;
// 	usint mk=m*k;
// 	string path="../data/"+to_string(numfeature)+"_"+to_string(m)+"_"+to_string(k)+"_"+to_string(repeatnum)+"_result.txt";

// 	fin.open(path, ios::in);
// 	fout.open("../data/tmp.txt", ios::out);
	
// 	usint i=0;
// 	while(getline(fin, line)){
// 		usint base=i*mk*repeatnum;
// 		fout << line;
// 		for(usint j=0; j<vectorsize; j++){
// 			fout <<  ", " << result[base+j].real();
// 		}
// 		if(i!=(n/(mk*repeatnum))-1)fout << endl;
// 		i+=1;
// 	}
// 	fout.close();
// 	fin.close();

// 	fin.open("../data/tmp.txt", ios::in);
// 	fout.open(path, ios::out);
// 	while(getline(fin, line)){
// 		fout << line << endl;
// 	}

// }


usint checkline(const string path){
	ifstream fin;
	string line;
	fin.open(path, ios::in);
	if (fin.fail()){
		cout << "empty" << endl;
		return 0;
	}

	usint count=0;

	while(getline(fin, line)){
		count +=1;
	}
	fin.close();
	cout << count << endl;
	return count;
}


void addRes(vector<string> newline, string path, usint iteration){
	fstream fout;	
	
	fout.open(path, ios::out | ios::app);
	if (fout.fail()){
		std::cerr << "Error!" << std::endl;
	}
	for(usint i=0;i<iteration+2;i++){
		fout << newline[i] << endl;	
	}
	fout.close();

}

// void SerializationUtils::codedwritePt(string* plain, complex<double>* result, usint n, usint m, usint k, usint numfeature){
// 	fstream fout;
// 	usint mk=m*k;
// 	string path="../data/"+to_string(numfeature)+"_"+to_string(m)+"_"+to_string(k)+"_"+to_string(0)+"_result.txt";

// 	fout.open(path, ios::out);
// 	if (fout.fail())
// 		{
// 			std::cerr << "Error!" << std::endl;
// 		}
// 	usint base=0;
// 	for(usint i=0; i<n; i++){
// 		fout << plain[i];
// 		fout <<  ", " << result[i].real();
// 		fout << endl;
// 	}
// 	fout.close();
// }

// void SerializationUtils::codedaddPt(complex<double>* result, usint n, usint m, usint k, usint numfeature){
// 	ifstream fin;
// 	fstream fout;
// 	string line;
// 	usint mk=m*k;
// 	string path="../data/"+to_string(numfeature)+"_"+to_string(m)+"_"+to_string(k)+"_"+to_string(0)+"_result.txt";

// 	fin.open(path, ios::in);
// 	fout.open("../data/tmp.txt", ios::out);
	
// 	usint i=0;
// 	while(getline(fin, line)){
// 		fout << line;
// 		fout <<  ", " << result[i].real();

// 		fout << endl;
// 		i+=1;
// 	}
// 	fout.close();
// 	fin.close();

// 	fin.open("../data/tmp.txt", ios::in);
// 	fout.open(path, ios::out);
// 	while(getline(fin, line)){
// 		fout << line << endl;
// 	}

// }

// map<string, complex<double>*> SerializationUtils::readresult(usint numfeature, usint m, usint k,usint repeatnum) {
// 	ifstream fin;
// 	string line;
// 	string vec;
// 	string path="../data/"+to_string(numfeature)+"_"+to_string(m)+"_"+to_string(k)+"_"+to_string(repeatnum)+"_result.txt";
// 	map<string, complex<double>*> table;

// 	fin.open(path, ios::in);
// 	if (fin.fail()){
// 		std::cerr << "Error!" << std::endl;
// 		return table;
// 	}
	

// 	while(getline(fin, line)){
// 		string tmpkey=line.substr(0, line.find(", "));
// 		vec=line.substr(line.find(", ")+2);
// 	    istringstream iss(vec);       
//     	string buffer;
// 		double num;
// 		complex<double>* tmpvalue=new complex<double>[numfeature];
// 		usint i=0;
// 	    while (getline(iss, buffer, ',')) {
// 			num= std::stod(buffer);
// 			if(i<numfeature)tmpvalue[i]=num;
// 			i+=1;
//     	}
// 		//cout << tmpkey << endl;
// 		table.insert(pair<string, complex<double>*>(tmpkey, tmpvalue));
// 	}
// 	fin.close();
// 	return table;
// }

// Plaintext samplestring(const usint numofsamples, const usint batchSize, const usint interval, const string path){
// 	ifstream fin;
// 	string line;

// 	fin.open(path, ios::in);
// 	if (fin.fail()){
// 		std::cerr << "Error!" << std::endl;
// 	}

// 	usint j=0;
// 	while(getline(fin, line) && j < samplenum){
// 		plain[j]=line.substr(0, line.find(", ["));
// 		j+=1;
// 	}
// 	while(j<n){
// 		plain[j]="_";
// 		j+=1;
// 	}
// 	fin.close();
// }

// void SerializationUtils::foldstring(string sentence, string* msgvec, usint n){
// 	istringstream iss(sentence);       
//     string buffer;

// 	usint i=0;
// 	while (getline(iss, buffer, ' ')) {
// 		if(i<n)msgvec[i]=buffer;
// 		i+=1;
//     }
// 	while(i<n){
// 		msgvec[i]="_";
// 		i+=1;
// 	}
// }


vector<string> readsentence(const usint size, usint batchblocknum, usint batchblocksize, const string path){
	ifstream fin;
	string line;
	string vec;
	vector<string> result;

	fin.open(path, ios::in);
	if (fin.fail()){
		std::cerr << "Error!, "  << path << std::endl;
		return result;
	}
	
	usint j=0;
	while(getline(fin, line)){
		
		if(j>=batchblocknum*batchblocksize){
			string tmpkey=line.substr(0, line.find(", ["));
			vec=line.substr(line.find(", [")+3);
			vec.erase(vec.find(']'), 1);

			istringstream iss(vec);       
			string buffer;
			usint i=0;
			bool commacheck = false;
			string tmp;


			while (getline(iss, buffer, ',')) {
				if(commacheck==true){
					commacheck = false;
					if(buffer.find('\'')<1024){
						buffer.erase(buffer.find('\''), 1);
					}
					if(buffer.find('\"')<1024){
						buffer.erase(buffer.find('\"'), 1);
					}

					tmp+=','+buffer;
					result.push_back(tmp);
					i+=1;
					if(i==size)break;
				
				}else{
					if(buffer[0]==' '){
						buffer.erase(0, 1);
					}
					if(buffer[0]=='\''){
						buffer.erase(buffer.find('\''), 1);
					}
					if(buffer[0]=='\''){
						buffer.erase(buffer.find('\"'), 1);
					}

					if(buffer.find('\'')<1024){
						buffer.erase(buffer.find('\''), 1);
						result.push_back(buffer);

						i+=1;
						if(i==size)break;
					}else{
						if(buffer.find('\"')<1024){
						buffer.erase(buffer.find('\"'), 1);
						result.push_back(buffer);
						i+=1;
						if(i==size)break;

						}else{	
							commacheck = true;
							tmp = buffer;
							
						}
					}
				}
				
				
				
			}
			while(i < size){
				result.push_back("<pad>");
				i+=1;
			}
		}


		j++;

		if(j==batchblocknum*batchblocksize+batchblocksize){
			break;
		}
	}
	fin.close();
	return result;
}


vector<usint> readlabels(usint batchblocknum, usint batchblocksize, const string path){
	ifstream fin;
	string line;
	string vec;
	vector<usint> result;

	fin.open(path, ios::in);
	if (fin.fail()){
		std::cerr << "Error!" << std::endl;
		return result;
	}
	
	usint j=0;
	while(getline(fin, line)){
		if(j>=batchblocknum*batchblocksize){
			string tmpkey=line.substr(0, line.find(", ["));
			usint num= std::stoi(tmpkey);
			result.push_back(num);
		}
		j++;
		if(j==batchblocknum*batchblocksize+batchblocksize)break;
	}
	fin.close();
	return result;
}



vector<double> readtexts(const usint size, const string filename, const double scale, const double pad){
	ifstream fin;
	string line;
	string vec;
	string path="../data/"+filename;
	vector<double> result;

	fin.open(path, ios::in);
	if (fin.fail()){
		std::cerr << "Error!" << std::endl;
		return result;
	}
	

	while(getline(fin, line)){
	    istringstream iss(line);       
    	string buffer;
		double num;
		usint i=0;
	    while (getline(iss, buffer, ',')) {
			num= std::stod(buffer) ;
			result.push_back(num / scale);
			i+=1;
			if(i==size)break;
    	}
		while(i < size){
			result.push_back(pad / scale);
			i+=1;
		}
	}
	fin.close();
	return result;
}

void writetext(const Plaintext inputtext, const usint size, const string filename, const double scale){
	fstream fout;
	string path="../data/"+filename;
    vector<double> plain = inputtext->GetRealPackedValue();

	fout.open(path, ios::out);
	if (fout.fail())
		{
			std::cerr << "Error!" << std::endl;
		}

	for(usint i=0; i<plain.size(); i++){

		fout << plain[i]*scale;
		if((i+1)%size==0){
			fout <<  endl;
		}else{
			fout << ", ";
		}
	}
	fout.close();
}


void mapandwritetext(const Plaintext inputtext, const usint size, const string filename, const double scale){
	fstream fout;
	string idxpath="../data/idxtoword_amazon.txt";
	string path="../data/"+filename;
	map<usint, string> idxset= getIndexToWord(idxpath);
	vector<double> plain = inputtext->GetRealPackedValue();
	
	fout.open(path, ios::out);
	if (fout.fail())
		{
			std::cerr << "Error!" << std::endl;
		}

	for(usint i=0; i<plain.size(); i++){
		usint idxtmp = (int)(plain[i]*scale+0.5);
		if(idxtmp < idxset.size())fout << idxset[idxtmp];
		if((i+1)%size==0){
			fout <<  endl;
		}else{
			if(idxtmp < idxset.size())fout << ", ";
		}
	}
	fout.close();

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

vector<usint> fixedIntArray(const usint size, const usint bound) {
	vector<usint> result(size);
	usint loga = (usint)log2(size);
	usint base = pow(2, loga/2);
	usint pointer = 0;
	for (usint i = 0; i < base; ++i) {
		for (usint j=0; j < i+1 ; j++){
			result[pointer] =i%bound;
			pointer+=1;
		}
	}
	return result;
}


vector<double> randomIntArrayNoised(const usint size, const usint bound, const usint noiselevel) {
	vector<double> result(size);
	for (usint i = 0; i < size; ++i) {
		result[i] = (double) (rand()%bound);
		result[i] += ((double)(rand()%1000))*(1/(1000*((double)(1<<noiselevel))));
	}
	return result;
}


vector<double> randomForRound(const usint size, const usint bound, const usint precision) {
	vector<double> result(size);
	for (usint i = 0; i < size; ++i) {
		result[i] = (double) (rand()%(bound-1));
		result[i] += ((double)(rand()%precision))/((double)precision);
		result[i] += 0.5/((double)precision);
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
	auto RingDim = log2(cc->GetRingDimension());
    auto QBitLength = cc->GetModulus().GetLengthForBase(2);
    auto PBitLength = P.GetLengthForBase(2);
    std::cout << "\nQ = (bit length: " << QBitLength
                << ")" << std::endl;
    std::cout << "P = (bit length: " << PBitLength << ")"
                << std::endl;
	std::cout << "RingDim = (bit length: " << RingDim << ")" << std::endl;
					


}

void bootSet1(CCParams<CryptoContextCKKSRNS> parameters, const usint scaleModSize){
    parameters.SetFirstModSize(scaleModSize+1);
    parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);
	parameters.SetSecretKeyDist(SPARSE_TERNARY);
    parameters.SetNumLargeDigits(0);
    parameters.SetKeySwitchTechnique(HYBRID);
}


void bootSet2(CryptoContext<DCRTPoly> cc, const PrivateKey<DCRTPoly> privateKey, const usint batchSize){
    cc->Enable(FHE);

	usint RingDim = log2(cc->GetRingDimension());
	
    usint levelBudgetElmt= (RingDim >15 ) ? 1 << (RingDim-14) : 2 ;  

    std::vector<uint32_t> levelBudget = {levelBudgetElmt, levelBudgetElmt};
	cout << "level budget: " << levelBudgetElmt << endl;
    cc->EvalBootstrapSetup(levelBudget, {0,0}, batchSize);
    //cc->EvalBootstrapSetup(levelBudget);

    const auto cryptoParamsCKKS =
    std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
          cc->GetCryptoParameters());
    usint depth = FHECKKSRNS::GetBootstrapDepth(levelBudget, cryptoParamsCKKS->GetSecretKeyDist());
	cout << "BootDepth: " << depth << endl;

    cc->EvalBootstrapKeyGen(privateKey, batchSize);
    //c2 = cc->EvalBootstrap(c2);
    cout<<"Boot Keygen Done"<<endl;

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

		if(tmp > max){
			max=tmp;
		}
	}
	
    usint prec = -log2(max);
    cout << "Estimated precision in bits:" << prec << ", max error: " << max << endl;
}

double countprecisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const bool show) {
	double tmp=0;
    vector<double> vals1 = vals->GetRealPackedValue();
	double prec=100;

	for (usint i = 0; i < size; ++i) {
		if(vals2[i]==resultnum){
			tmp+=1;
		}
	}
	if(show)cout << "True: " << tmp << ", Estimated: " << vals1[0] << endl;
	tmp = (vals1[0]-tmp);
	if(tmp < 0)tmp= -tmp;
	if(prec > -log2(tmp))prec = -log2(tmp);
	

	

	return prec;
}

double countSIMDprecisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const bool show) {
	double tmp=0;
    vector<double> vals1 = vals->GetRealPackedValue();
	usint num = vals1.size() / size;
	double prec=100;

	for (usint j=0; j< num; j++){
		for (usint i = 0; i < size; ++i) {
			if(vals2[i]==num*resultnum+j){
				tmp+=1;
			}
		}
		if(show)cout << "True: " << tmp << ", Estimated: " << vals1[j*size] << endl;
		tmp = (vals1[j*size]-tmp);
		if(tmp < 0)tmp= -tmp;
		if(prec > -log2(tmp))prec = -log2(tmp);
	}

	

	return prec;
}

double CodedcountprecisionMute(const Plaintext vals, const vector<double> vals2, const usint size, const double resultnum, const bool show) {
	double tmp=0;
    vector<double> vals1 = vals->GetRealPackedValue();
	double prec=100;

	for (usint i = 0; i < size; ++i) {
		if(vals2[i]==resultnum){
			tmp+=1;
		}
	}
	if(show)cout << "True: " << tmp << ", Estimated: " << vals1[0] << endl;
	tmp = (vals1[0]-tmp);
	if(tmp < 0)tmp= -tmp;
	if(prec > -log2(tmp))prec = -log2(tmp);
	

	

	return prec;
}


void binaryprecisiontrack(const Plaintext vals, const usint size,  const vector<double> origin) {
	double max = 0;
	double tmp;
	double tmp2;
	usint maxloc = 0;
    vector<double> vals1 = vals->GetRealPackedValue();

	for (usint i = 0; i < size; ++i) {
		tmp2 = vals1[i];
		if(tmp2 < 0)tmp2= -tmp2;
		tmp = (tmp2-1.0);
		if(tmp < 0)tmp= -tmp;
		if(tmp > tmp2)tmp=tmp2;

		if(tmp > max){
			max=tmp;
			maxloc=i;
		}
	}
	
    usint prec = -log2(max);
	cout << "Max origin: " << origin[maxloc] << endl;
    cout << "Estimated precision in bits:" << prec << ", max error: " << max << endl;
}

// usint argmaxerror(const Plaintext vals, const usint size) {
// 	double max = 0;
// 	double tmp;
// 	double tmp2;
// 	usint arg;
//     vector<double> vals1 = vals->GetRealPackedValue();

// 	for (usint i = 0; i < size; ++i) {
// 		tmp2 = vals1[i];
// 		if(tmp2 < 0)tmp2= -tmp2;
// 		tmp = (tmp2-1.0);
// 		if(tmp < 0)tmp= -tmp;
// 		if(tmp > tmp2)tmp=tmp2;

// 		if(tmp > max){
// 			max=tmp;
// 			arg=i;
// 		}
// 	}
	

// 	return arg;
// }

// usint argmax(const Plaintext vals, const usint size) {
// 	double max = 0;
// 	double tmp;
// 	usint arg=0;
//     vector<double> vals1 = vals->GetRealPackedValue();

// 	for (usint i = 0; i < size; ++i) {
// 		tmp = vals1[i];
// 		if(tmp < 0)tmp= -tmp;

// 		if(tmp > max){
// 			max=tmp;
// 			arg=i;
// 		}
// 	}
	

// 	return arg;
// }

void roundprecision(const vector<double> vals1, const vector<double> vals2, const usint size) {
	double tmp;
	usint count=0;
	for (usint i = 0; i < size; ++i) {
		tmp = round(vals1[i])-round(vals2[i]);
		if(((int)tmp) %2 == 0)count++;
	}
	

    cout << "accurate num:" << count << ", accuracy: " << (double)count/(double)size << endl;
}

}
