#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "logger.hpp"
#include <omp.h>
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <random>

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
const string DATAFOLDER = "experimentData";
const int numberOfSamples = 16;
const int numberOfVariants = 100000;
const int blockSize = 25000;

void saveEncryptedData(string fileName, Ciphertext<DCRTPoly> ciphertext){

    if (!Serial::SerializeToFile(DATAFOLDER + fileName, ciphertext, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext to ciphertext.txt" << std::endl;
    }else{
        std::cout << "The ciphertexts have been serialized." << std::endl;
    }
}

void saveEncryptedResult(string fileName, vector<Ciphertext<DCRTPoly>> result){

    if (!Serial::SerializeToFile(DATAFOLDER + fileName, result, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext to result.txt" << std::endl;
    }else{
        std::cout << "The result has been serialized." << std::endl;
    }
}

void saveCryptoContext(CryptoContext<DCRTPoly> cryptoContext){

    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
    }else{
        std::cout << "The cryptocontext has been serialized." << std::endl;
    }


}

void savePublicKey(PublicKey<DCRTPoly> publicKey){

    if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", publicKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
    }else{
        std::cout << "The public key has been serialized." << std::endl;
    }
   
}

void saveSecretKey(PrivateKey<DCRTPoly> secretKey){

    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private.txt", secretKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
    }else{
        std::cout << "The secret key has been serialized." << std::endl;
    }
   
   
}

void saveRelinearizationKey(CryptoContext<DCRTPoly> cryptoContext){
    std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult.txt", std::ios::out | std::ios::binary);
    if (emkeyfile.is_open()) {
        if (cryptoContext->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval mult keys to "
                         "key-eval-mult.txt"
                      << std::endl;
        }
        std::cout << "The eval mult keys have been serialized." << std::endl;

        emkeyfile.close();
    }
    else {
        std::cerr << "Error serializing eval mult keys" << std::endl;
    }
}

void saveRotationKey(CryptoContext<DCRTPoly> cryptoContext){
    std::ofstream erkeyfile(DATAFOLDER + "/" + "key-eval-rot.txt", std::ios::out | std::ios::binary);
    if (erkeyfile.is_open()) {
        if (cryptoContext->SerializeEvalAutomorphismKey(erkeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval rotation keys to "
                         "key-eval-rot.txt"
                      << std::endl;
        }
        std::cout << "The eval rotation keys have been serialized." << std::endl;

        erkeyfile.close();
    }
    else {
        std::cerr << "Error serializing eval rotation keys" << std::endl;
    }
}

void saveSumKey(CryptoContext<DCRTPoly> cryptoContext){
    std::ofstream eskeyfile(DATAFOLDER + "/" + "key-eval-sum.txt", std::ios::out | std::ios::binary);
    if (eskeyfile.is_open()) {
        if (cryptoContext->SerializeEvalSumKey(eskeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval rotation keys to "
                         "key-eval-sum.txt"
                      << std::endl;
        }
        std::cout << "The eval sum keys have been serialized." << std::endl;

        eskeyfile.close();
    }
    else {
        std::cerr << "Error serializing eval sum keys" << std::endl;
    }
}

void generateData(){
    std::string variants[3] = { "10", "01", "00"};
    ofstream file("samples.txt");

    for (int i = 0; i < numberOfVariants; i++){

        string line;

        for (int j = 0; j < 4; j++){
            int index = std::rand() % 3;
            line.append(variants[index]);
            if (j != numberOfSamples - 1){
                line.append(" ");
            }
        }

        file << line;

        if ( i != numberOfVariants - 1){
            file << endl;
        }

    }

    file.close();

}

void generateSamples(){

    for (int i=0; i < 4; i++){
        string data;
        ifstream file("samples.txt");
        ofstream sampleFile("sample_" + to_string(i+1) + ".txt");
        string line;
        int counter = 1;

        while (getline (file, data)) {

            line = data;
            std::string::iterator end_pos = std::remove(line.begin(), line.end(), ' ');
            line.erase(end_pos, line.end());
            sampleFile << line.substr(i*2, 2);
            if (counter != numberOfVariants){
                sampleFile << endl;
            }
           
            counter++;
       
        }

        file.close();
        sampleFile.close();
    }

    std::ofstream outputFile("sample_c.txt");

    if (outputFile.is_open()) {
        for (int i = 0; i < numberOfVariants; ++i) {
            outputFile << "00";
            if (i < numberOfVariants - 1) {
                outputFile << std::endl; 
            }
        }

        outputFile.close(); 
        std::cout << "File created successfully." << std::endl;
    } else {
        std::cerr << "Error: Unable to create the file." << std::endl;
    }


}

void encryptVCFData(string fileName, CryptoContext<DCRTPoly> cryptoContext, PublicKey<DCRTPoly> publicKey, int sampleIndex){

           
    for (int i=0; i < 2; i++){

        ifstream file(fileName);
        std::vector<int64_t> vectorOfElement;
        string data;
        int counter = 0;
        int ciphertextCounter = 0;
               
        while (getline (file, data)) {

            string line = data;
            std::string::iterator end_pos = std::remove(line.begin(), line.end(), ' ');
            line.erase(end_pos, line.end());

            string data_i(1,line[i]);
            int element = stoi(data_i);
            vectorOfElement.push_back(element);
            counter++;

            if (counter % blockSize == 0){

                ciphertextCounter++;
                Plaintext plaintext;
                plaintext = cryptoContext->MakePackedPlaintext(vectorOfElement);
                auto ciphertexts = cryptoContext->Encrypt(publicKey, plaintext);
                saveEncryptedData("/sample_" + to_string(sampleIndex) + "_" + "ct_" + to_string(ciphertextCounter) + "_" + to_string(i) + ".txt", ciphertexts);
                vectorOfElement = {};
            }
                   
        }

        file.close();
    }  

}


void generateCryptoContext(vector<string> fileNames){
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(7340033);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetRingDim(65536);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
   
    cout << cryptoContext->GetRingDimension() << endl;

    std::cout << "Security Level: " << parameters.GetSecurityLevel() << std::endl;

    std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
   
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(MULTIPARTY);

    KeyPair<DCRTPoly> keyPair;

    keyPair = cryptoContext->KeyGen();

    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});
    cryptoContext->EvalSumKeyGen(keyPair.secretKey, keyPair.publicKey);

    //Save the cryptocontext, encrypted data, public key and secret key

    saveCryptoContext(cryptoContext);
    savePublicKey(keyPair.publicKey);
    saveSecretKey(keyPair.secretKey);
    saveRelinearizationKey(cryptoContext);
    saveRotationKey(cryptoContext);
    saveSumKey(cryptoContext);


    //Encrypt sample data


    for (int i = 0; i < fileNames.size(); i++){
       
        string sampleFileName = fileNames[i];
        encryptVCFData(sampleFileName, cryptoContext, keyPair.publicKey, i+1);

    }

    //Clear the context and clear the keys
    cryptoContext->ClearEvalMultKeys();
    cryptoContext->ClearEvalAutomorphismKeys();
    cryptoContext->ClearEvalSumKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
}

