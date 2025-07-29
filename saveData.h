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
const string DATAFOLDER = "/dev/shm/experimentData";
const int numberOfSamples = 16;
const int numberOfVariants = 1600000;
const int blockSize = 25000;
const int numberOfParties = 4;

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

void saveEncryptedResult2(string fileName, Ciphertext<DCRTPoly> result){

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

void saveSecretKey(PrivateKey<DCRTPoly> secretKey, int keyId) {
    
    std::string filename = DATAFOLDER + "/key-private-" + std::to_string(keyId) + ".txt";

    if (!Serial::SerializeToFile(filename, secretKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of private key to " << filename << std::endl;
    } else {
        std::cout << "The secret key has been serialized to " << filename << std::endl;
    }
}

void saveMulKey(CryptoContext<DCRTPoly> cryptoContext){
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

void generateCryptoContext2P(std::vector<std::string> fileNames, int multDepth) {
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(7340033);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetRingDim(65536);
    // You might want to set other parameters for security, e.g., SetSecurityLevel, SetStandardDeviation, SetSecretKeyDist, SetBatchSize, SetDigitSize, SetScalingModSize, SetMultiplicationTechnique
    // For simplicity, using only the ones you provided.
    // parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext = lbcrypto::GenCryptoContext(parameters);
   
    std::cout << "Ring Dimension: " << cryptoContext->GetRingDimension() << std::endl;
    // std::cout << "Security Level: " << parameters.GetSecurityLevel() << std::endl; // This might output 'Undefined' if not explicitly set

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

    // Key Generation for 2 parties
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair1;
    keyPair1 = cryptoContext->KeyGen();
    auto keyPair2 = cryptoContext->MultipartyKeyGen(keyPair1.publicKey); // Party 2's key depends on Party 1's public key

    // EvalMult Key Generation for 2 parties
    auto evalMultKey1 = cryptoContext->KeySwitchGen(keyPair1.secretKey, keyPair1.secretKey);
    auto evalMultKey2 = cryptoContext->MultiKeySwitchGen(keyPair2.secretKey, keyPair2.secretKey, evalMultKey1);

    auto evalMult12 = cryptoContext->MultiAddEvalKeys(evalMultKey1, evalMultKey2, keyPair2.publicKey->GetKeyTag());

    auto evalMult212 = cryptoContext->MultiMultEvalKey(keyPair2.secretKey, evalMult12, keyPair2.publicKey->GetKeyTag());
    auto evalMult112 = cryptoContext->MultiMultEvalKey(keyPair1.secretKey, evalMult12, keyPair2.publicKey->GetKeyTag());
    
    auto evalMultFinal = cryptoContext->MultiAddEvalMultKeys(evalMult112, evalMult212, keyPair2.publicKey->GetKeyTag());

    cryptoContext->InsertEvalMultKey({evalMultFinal});

    // EvalSum Key Generation for 2 parties
    cryptoContext->EvalSumKeyGen(keyPair1.secretKey);
    auto evalSumKeys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cryptoContext->GetEvalSumKeyMap(keyPair1.secretKey->GetKeyTag()));
    auto evalSumKeys2 = cryptoContext->MultiEvalSumKeyGen(keyPair2.secretKey, evalSumKeys, keyPair2.publicKey->GetKeyTag());

    auto evalSumKeysJoin = cryptoContext->MultiAddEvalSumKeys(evalSumKeys, evalSumKeys2, keyPair2.publicKey->GetKeyTag());
    cryptoContext->InsertEvalSumKey(evalSumKeysJoin);

    // Save the cryptocontext, encrypted data, public key and secret key
    saveCryptoContext(cryptoContext);
    savePublicKey(keyPair2.publicKey); // Save the final combined public key
    saveSecretKey(keyPair1.secretKey, 1);
    saveSecretKey(keyPair2.secretKey, 2);
    saveMulKey(cryptoContext);
    saveRotationKey(cryptoContext); // Assuming EvalSum implies rotations
    saveSumKey(cryptoContext);

    // Encrypt sample data
    for (size_t i = 0; i < fileNames.size(); ++i){
        std::string sampleFileName = fileNames[i];
        encryptVCFData(sampleFileName, cryptoContext, keyPair2.publicKey, i + 1); // Encrypt with the final public key
    }

    // Clear the context and clear the keys
    cryptoContext->ClearEvalMultKeys();
    cryptoContext->ClearEvalAutomorphismKeys(); // EvalSum keys are automorphism keys
    cryptoContext->ClearEvalSumKeys(); // This might be redundant if ClearEvalAutomorphismKeys clears them
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
}


void generateCryptoContext4P(vector<string> fileNames, int multDepth){
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(7340033);
    parameters.SetMultiplicativeDepth(multDepth);
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
    auto keyPair2 = cryptoContext->MultipartyKeyGen(keyPair.publicKey);
    auto keyPair3 = cryptoContext->MultipartyKeyGen(keyPair2.publicKey);
    auto keyPair4 = cryptoContext->MultipartyKeyGen(keyPair3.publicKey);

    auto evalMultKey = cryptoContext->KeySwitchGen(keyPair.secretKey, keyPair.secretKey);
    auto evalMultKey2 = cryptoContext->MultiKeySwitchGen(keyPair2.secretKey, keyPair2.secretKey, evalMultKey);
    auto evalMultKey3 = cryptoContext->MultiKeySwitchGen(keyPair3.secretKey, keyPair3.secretKey, evalMultKey);
    auto evalMultKey4 = cryptoContext->MultiKeySwitchGen(keyPair4.secretKey, keyPair4.secretKey, evalMultKey);

    auto evalMult12 = cryptoContext->MultiAddEvalKeys(evalMultKey, evalMultKey2, keyPair2.publicKey->GetKeyTag());
    auto evalMult123 = cryptoContext->MultiAddEvalKeys(evalMult12, evalMultKey3, keyPair3.publicKey->GetKeyTag());
    auto evalMult1234 = cryptoContext->MultiAddEvalKeys(evalMult123, evalMultKey4, keyPair4.publicKey->GetKeyTag());

    auto evalMult41234 = cryptoContext->MultiMultEvalKey(keyPair4.secretKey, evalMult1234, keyPair4.publicKey->GetKeyTag());
    auto evalMult31234 = cryptoContext->MultiMultEvalKey(keyPair3.secretKey, evalMult1234, keyPair4.publicKey->GetKeyTag());
    auto evalMult21234 = cryptoContext->MultiMultEvalKey(keyPair2.secretKey, evalMult1234, keyPair4.publicKey->GetKeyTag());
    auto evalMult11234 = cryptoContext->MultiMultEvalKey(keyPair.secretKey, evalMult1234, keyPair4.publicKey->GetKeyTag());
    
    auto evalMult341234 = cryptoContext->MultiAddEvalMultKeys(evalMult41234, evalMult31234, evalMult41234->GetKeyTag());
    auto evalMult2341234 = cryptoContext->MultiAddEvalMultKeys(evalMult21234, evalMult341234, evalMult21234->GetKeyTag());
    auto evalMultFinal = cryptoContext->MultiAddEvalMultKeys(evalMult11234, evalMult2341234, keyPair4.publicKey->GetKeyTag());

    cryptoContext->InsertEvalMultKey({evalMultFinal});

    cryptoContext->EvalSumKeyGen(keyPair.secretKey);

    auto evalSumKeys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cryptoContext->GetEvalSumKeyMap(keyPair.secretKey->GetKeyTag()));
    auto evalSumKeys2 = cryptoContext->MultiEvalSumKeyGen(keyPair2.secretKey, evalSumKeys, keyPair2.publicKey->GetKeyTag());
    auto evalSumKeys3 = cryptoContext->MultiEvalSumKeyGen(keyPair3.secretKey, evalSumKeys, keyPair3.publicKey->GetKeyTag());
    auto evalSumKeys4 = cryptoContext->MultiEvalSumKeyGen(keyPair4.secretKey, evalSumKeys, keyPair4.publicKey->GetKeyTag());


    auto evalSumKeys12 = cryptoContext->MultiAddEvalSumKeys(evalSumKeys, evalSumKeys2, keyPair2.publicKey->GetKeyTag());
    auto evalSumKeys123 = cryptoContext->MultiAddEvalSumKeys(evalSumKeys3, evalSumKeys12, keyPair3.publicKey->GetKeyTag());
    auto evalSumKeysJoin = cryptoContext->MultiAddEvalSumKeys(evalSumKeys4, evalSumKeys123, keyPair4.publicKey->GetKeyTag());

    cryptoContext->InsertEvalSumKey(evalSumKeysJoin);

    //Save the cryptocontext, encrypted data, public key and secret key

    saveCryptoContext(cryptoContext);
    savePublicKey(keyPair4.publicKey);
    saveSecretKey(keyPair.secretKey, 1);
    saveSecretKey(keyPair2.secretKey, 2);
    saveSecretKey(keyPair3.secretKey, 3);
    saveSecretKey(keyPair4.secretKey, 4);
    saveMulKey(cryptoContext);
    saveRotationKey(cryptoContext);
    saveSumKey(cryptoContext);


    //Encrypt sample data


    for (size_t i = 0; i < fileNames.size(); i++){
       
        string sampleFileName = fileNames[i];
        encryptVCFData(sampleFileName, cryptoContext, keyPair4.publicKey, i+1);

    }

    //Clear the context and clear the keys
    cryptoContext->ClearEvalMultKeys();
    cryptoContext->ClearEvalAutomorphismKeys();
    cryptoContext->ClearEvalSumKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
}

void generateCryptoContext8P(std::vector<std::string> fileNames, int multDepth) {
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(7340033);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetRingDim(65536);
    // You might want to set other parameters for security, e.g., SetSecurityLevel, SetStandardDeviation, SetSecretKeyDist, SetBatchSize, SetDigitSize, SetScalingModSize, SetMultiplicationTechnique
    // For simplicity, using only the ones you provided.
    // parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext = lbcrypto::GenCryptoContext(parameters);
   
    std::cout << "Ring Dimension: " << cryptoContext->GetRingDimension() << std::endl;
    // std::cout << "Security Level: " << parameters.GetSecurityLevel() << std::endl;

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

    // Key Generation for 8 parties
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair[8]; // Array to hold key pairs
    keyPair[0] = cryptoContext->KeyGen();
    for (int i = 1; i < 8; ++i) {
        keyPair[i] = cryptoContext->MultipartyKeyGen(keyPair[i-1].publicKey);
    }
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> finalPublicKey = keyPair[7].publicKey; // Final combined public key

    // EvalMult Key Generation for 8 parties
    std::vector<lbcrypto::EvalKey<lbcrypto::DCRTPoly>> evalMultKeys(8);
    evalMultKeys[0] = cryptoContext->KeySwitchGen(keyPair[0].secretKey, keyPair[0].secretKey);
    for (int i = 1; i < 8; ++i) {
        evalMultKeys[i] = cryptoContext->MultiKeySwitchGen(keyPair[i].secretKey, keyPair[i].secretKey, evalMultKeys[0]);
    }

    // Additive combination of EvalMult keys
    lbcrypto::EvalKey<lbcrypto::DCRTPoly> currentAddEvalMultKey = evalMultKeys[0];
    for (int i = 1; i < 8; ++i) {
        currentAddEvalMultKey = cryptoContext->MultiAddEvalKeys(currentAddEvalMultKey, evalMultKeys[i], keyPair[i].publicKey->GetKeyTag());
    }
    
    // Multiplicative combination for each party
    std::vector<lbcrypto::EvalKey<lbcrypto::DCRTPoly>> multiplicativeEvalMultKeys(8);
    for (int i = 0; i < 8; ++i) {
        multiplicativeEvalMultKeys[i] = cryptoContext->MultiMultEvalKey(keyPair[i].secretKey, currentAddEvalMultKey, finalPublicKey->GetKeyTag());
    }

    // Final additive combination of multiplicative parts
    lbcrypto::EvalKey<lbcrypto::DCRTPoly> evalMultFinal = multiplicativeEvalMultKeys[0];
    for (int i = 1; i < 8; ++i) {
        evalMultFinal = cryptoContext->MultiAddEvalMultKeys(evalMultFinal, multiplicativeEvalMultKeys[i], finalPublicKey->GetKeyTag());
    }

    cryptoContext->InsertEvalMultKey({evalMultFinal});

    // EvalSum Key Generation for 8 parties
    cryptoContext->EvalSumKeyGen(keyPair[0].secretKey);
    auto evalSumKeyMap = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cryptoContext->GetEvalSumKeyMap(keyPair[0].secretKey->GetKeyTag()));
    
    std::vector<decltype(evalSumKeyMap)> individualEvalSumMaps(8);
    individualEvalSumMaps[0] = evalSumKeyMap;
    for (int i = 1; i < 8; ++i) {
        individualEvalSumMaps[i] = cryptoContext->MultiEvalSumKeyGen(keyPair[i].secretKey, evalSumKeyMap, keyPair[i].publicKey->GetKeyTag());
    }

    // Final additive combination of EvalSum keys
    auto evalSumKeysJoin = individualEvalSumMaps[0];
    for (int i = 1; i < 8; ++i) {
        evalSumKeysJoin = cryptoContext->MultiAddEvalSumKeys(evalSumKeysJoin, individualEvalSumMaps[i], finalPublicKey->GetKeyTag());
    }
    cryptoContext->InsertEvalSumKey(evalSumKeysJoin);

    // Save the cryptocontext, encrypted data, public key and secret key
    saveCryptoContext(cryptoContext);
    savePublicKey(finalPublicKey); // Save the final combined public key
    for (int i = 0; i < 8; ++i) {
        saveSecretKey(keyPair[i].secretKey, i + 1);
    }
    saveMulKey(cryptoContext);
    saveRotationKey(cryptoContext);
    saveSumKey(cryptoContext);

    // Encrypt sample data
    for (size_t i = 0; i < fileNames.size(); ++i){
        std::string sampleFileName = fileNames[i];
        encryptVCFData(sampleFileName, cryptoContext, finalPublicKey, i + 1); // Encrypt with the final public key
    }

    // Clear the context and clear the keys
    cryptoContext->ClearEvalMultKeys();
    cryptoContext->ClearEvalAutomorphismKeys();
    cryptoContext->ClearEvalSumKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
}
