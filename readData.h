#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include <omp.h>
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <random>

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;


Ciphertext<DCRTPoly> readEncryptedData(string fileName){

    Ciphertext<DCRTPoly> ciphertextRead;
    Serial::DeserializeFromFile(DATAFOLDER + fileName, ciphertextRead, SerType::BINARY);
    return ciphertextRead;

}

PublicKey<DCRTPoly> readPublicKey(string fileName){
    PublicKey<DCRTPoly> pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + fileName, pk, SerType::BINARY) == false) {
        std::cerr << "Could not read public key" << std::endl;
    }else{
        std::cout << "The public key has been deserialized." << std::endl;
    }
    return pk;

}

PrivateKey<DCRTPoly> readSecretKey(string fileName){
    PrivateKey<DCRTPoly> sk;
    if (Serial::DeserializeFromFile(DATAFOLDER + fileName, sk, SerType::BINARY) == false) {
        std::cerr << "Could not read secret key" << std::endl;
    }else{
        std::cout << "The secret key has been deserialized." << std::endl;
    }
    return sk;
}

vector<string> readParameters(string parameterFile){ //read parameter file that contains the sample files

    ifstream file(parameterFile);
    string line;
    vector<string> files;

    while (std::getline(file, line)) {
        std::size_t equals_pos = line.find("=");
        std::string key = line.substr(0, equals_pos);
        std::string value = line.substr(equals_pos + 1);
        std::size_t comma_pos = 0;
        while (comma_pos != std::string::npos) {
            std::size_t next_comma_pos = value.find(",", comma_pos + 1);
            std::string filename = value.substr(comma_pos, next_comma_pos - comma_pos);
            std::size_t pos = filename.find(",");
            if (pos != std::string::npos) {
                filename.erase(pos, 1);
            }
            files.push_back(filename);
            comma_pos = next_comma_pos;
        }

    }

    if (numberOfSamples <= 4){
        files.pop_back();
    }

    return files;

}

CryptoContext<DCRTPoly> readCryptoContext(string fileName){
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + fileName, cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
    }else{
        std::cout << "The cryptocontext has been deserialized." << std::endl;
    }

    return cc;

}

Ciphertext<DCRTPoly> getCiphertextNot(CryptoContext<DCRTPoly> cc,  PublicKey<DCRTPoly> pk){

    std::vector<int64_t> elementNot;

    for (int i = 0; i < blockSize; i++){

        elementNot.push_back(1);
    }

    Plaintext plaintextNot = cc->MakePackedPlaintext(elementNot);
    auto ciphertextNot = cc->Encrypt(pk, plaintextNot);

    return ciphertextNot;

}

Ciphertext<DCRTPoly> getCiphertextNumSamples(CryptoContext<DCRTPoly> cc,  PublicKey<DCRTPoly> pk){

    std::vector<int64_t> elementNumSamples;

    for (int i = 0; i < blockSize; i++){

        elementNumSamples.push_back(numberOfSamples * 2);
    }

    Plaintext plaintextNumSamples = cc->MakePackedPlaintext(elementNumSamples);
    auto ciphertextNumSamples = cc->Encrypt(pk, plaintextNumSamples);

    return ciphertextNumSamples;

}

Ciphertext<DCRTPoly> getCiphertextNumSamplesDeNovo(CryptoContext<DCRTPoly> cc,  PublicKey<DCRTPoly> pk){

    std::vector<int64_t> elementNumSamples;

    for (int i = 0; i < blockSize; i++){

        elementNumSamples.push_back(numberOfSamples);
    }

    Plaintext plaintextNumSamples = cc->MakePackedPlaintext(elementNumSamples);
    auto ciphertextNumSamples = cc->Encrypt(pk, plaintextNumSamples);

    return ciphertextNumSamples;

}


std::vector<Ciphertext<DCRTPoly>> getQuery(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk){
    Ciphertext<DCRTPoly> query;
    std::vector<Ciphertext<DCRTPoly>> queryVec;
    std::vector<int64_t> elements = {1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0};

    for (int i = 0; i < numberOfSamples * 2 ; i++){
        std::vector<int64_t> elementVec;
        if (i <= 8){
            for (int j = 0; j < blockSize; j++){
                elementVec.push_back(elements[i]);
           
            }
        }else{
            for (int j = 0; j < blockSize; j++){
                elementVec.push_back(elements[8]);
           
            }
        }
        

        Plaintext plaintext = cc->MakePackedPlaintext(elementVec);
        query = cc->Encrypt(pk, plaintext);
        queryVec.push_back(query);
    }

    return queryVec;
}

Ciphertext<DCRTPoly> getRandomVector(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk, size_t blockSize, int minValue, int maxValue) {

    std::vector<int64_t> randomVec(blockSize);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(minValue, maxValue);

    std::generate(randomVec.begin(), randomVec.end(), [&]() { return dis(gen); });

    Plaintext randomPlaintext = cc->MakePackedPlaintext(randomVec);
    auto randomCiphertext = cc->Encrypt(pk, randomPlaintext);

    return randomCiphertext;
}

vector<vector<string>> getSampleFilenames(){

    vector<vector<string>> sampleFilenames;

    for (int j = 1; j < numberOfVariants/blockSize + 1; j++){

        vector<string> sampleFilenames0;
       
        for (int i = 1; i < numberOfSamples + 1; i++){

            if (i < 5){
                sampleFilenames0.push_back("/sample_" + to_string(i) + "_ct_" + to_string(j) + "_0.txt");
                sampleFilenames0.push_back("/sample_" + to_string(i) + "_ct_" + to_string(j) + "_1.txt");
            }else{
                sampleFilenames0.push_back("/sample_5_ct_" + to_string(j) + "_0.txt");
                sampleFilenames0.push_back("/sample_5_ct_" + to_string(j) + "_1.txt");
            }

        }

        sampleFilenames.push_back(sampleFilenames0);
    }

    return sampleFilenames;

}

vector<vector<string>> getSampleFilenamesDeNovo(){

    vector<vector<string>> sampleFilenames;

    for (int j = 1; j < numberOfVariants/blockSize + 1; j++){

        vector<string> sampleFilenames0;
       
        for (int i = 1; i < numberOfSamples + 1; i++){

            if (i < numberOfSamples/2 + 1){
                int k = i;
                if (k > 4){
                    k = k % 4;
                    if (k == 0){
                        k = 4;
                    }
                }
                sampleFilenames0.push_back("/sample_" + to_string(k) + "_ct_" + to_string(j) + "_0.txt");
                sampleFilenames0.push_back("/sample_" + to_string(k) + "_ct_" + to_string(j) + "_1.txt");
            }else{
                sampleFilenames0.push_back("/sample_5_ct_" + to_string(j) + "_0.txt");
                sampleFilenames0.push_back("/sample_5_ct_" + to_string(j) + "_1.txt");
            }

        }

        sampleFilenames.push_back(sampleFilenames0);
    }

    return sampleFilenames;

}

int readEvalMultKeys(CryptoContext<DCRTPoly> cc){

    std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
    if (!emkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
        return 1;
    }
    if (cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval mult key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval mult keys." << std::endl;

    return 0;

}

int readEvalRotationKeys(CryptoContext<DCRTPoly> cc){

    std::ifstream erkeys(DATAFOLDER + "/key-eval-rot.txt", std::ios::in | std::ios::binary);
    if (!erkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-rot.txt" << std::endl;
        return 1;
    }
    if (cc->DeserializeEvalAutomorphismKey(erkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval rotation key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval rotation keys." << std::endl;

    return 0;

}

int readEvalSumKeys(CryptoContext<DCRTPoly> cc){

    std::ifstream eskeys(DATAFOLDER + "/key-eval-sum.txt", std::ios::in | std::ios::binary);
    if (!eskeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-sum.txt" << std::endl;
        return 1;
    }
    if (cc->DeserializeEvalSumKey(eskeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval sum key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval sum keys." << std::endl;

    return 0;

}
