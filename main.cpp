#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "saveData.h"
#include "readData.h"
#include "logger.hpp"
#include <omp.h>
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <random>
#include <omp.h>

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;


Ciphertext<DCRTPoly> filterVariants(std::vector<string> filenames, std::vector<Ciphertext<DCRTPoly>> query, CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ciphertextNot, Ciphertext<DCRTPoly> ciphertextNumSamples){

    std::vector<Ciphertext<DCRTPoly>> ciphertextsVec;
   
    std::vector<Ciphertext<DCRTPoly>> ciphertextsXOR;

    for (int j = 0; j < numberOfSamples*2; j++){

        auto ciphertextRead = readEncryptedData(filenames[j]);
        auto ciphertextDifference_0 = cc->EvalSub(ciphertextRead, query[j]);
        auto ciphertextDifference_1 = cc->EvalSub(query[j], ciphertextRead);
        auto ciphertextMul_0 = cc->EvalMult(ciphertextDifference_0, ciphertextDifference_1);
        auto ciphertextResult_0 = cc->EvalAdd(ciphertextMul_0, ciphertextNot);

        ciphertextsXOR.push_back(ciphertextResult_0);
    }


    auto ciphertextsXOR_0 = cc->EvalAddMany(ciphertextsXOR);
    auto ciphertext_Result =cc->EvalSub(ciphertextsXOR_0, ciphertextNumSamples);

    return ciphertext_Result;

}


Ciphertext<DCRTPoly> sumFilteringResults(CryptoContext<DCRTPoly> cc, std::vector<Ciphertext<DCRTPoly>> ciphertextsFilteringResult){

    auto result = cc->EvalAddMany(ciphertextsFilteringResult);
    return result;
}

Ciphertext<DCRTPoly> sum(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> sumResult){

    auto ct = cc->EvalSum(sumResult, blockSize);
    return ct;
}

//Decrypt the sum result
Plaintext getResult(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk, Ciphertext<DCRTPoly> encryptedResult){

    Plaintext plaintextResult;
    cc->Decrypt(sk, encryptedResult, &plaintextResult);
    return plaintextResult;
   
}


int main() {

    omp_set_num_threads(1);


    // Read the cryptocontext and keys

    CryptoContext<DCRTPoly> cc = readCryptoContext("/cryptocontext.txt");
    PublicKey<DCRTPoly> pk = readPublicKey("/key-public.txt");

    readEvalMultKeys(cc);
    readEvalRotationKeys(cc);
    readEvalSumKeys(cc);

    auto ciphertextNot = getCiphertextNot(cc, pk);

    auto ciphertextNumSamples = getCiphertextNumSamples(cc,pk);


    //Get query

    std::vector<Ciphertext<DCRTPoly>> query = getQuery(cc, pk);

    //Get random vector 

    auto randomCiphertext = getRandomVector(cc, pk, blockSize, 1, 1000);

    //Get sample filenames

    vector<vector<string>> sampleFilenames = getSampleFilenames();
    PrivateKey<DCRTPoly> sk = readSecretKey("/key-private.txt");

    auto startFiltering = high_resolution_clock::now();

    std::vector<Ciphertext<DCRTPoly>> filteringResults;

    //Filter variants in each block

    #pragma omp parallel for

    for (int i = 0; i < numberOfVariants/blockSize; i++){

        Ciphertext<DCRTPoly> ciphertextsFilteringResult = filterVariants(sampleFilenames[i], query, cc, ciphertextNot, ciphertextNumSamples);

        auto ciphertextsFilteringResultRandom = cc->EvalMult(ciphertextsFilteringResult, randomCiphertext);  
        filteringResults.push_back(ciphertextsFilteringResultRandom);

    }

    //Shuffle the ciphertexts in the filteringResults vector

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(filteringResults.begin(), filteringResults.end(), g);

    auto endFiltering = high_resolution_clock::now();

    auto durationFiltering = duration_cast<milliseconds>(endFiltering - startFiltering);

    int millisecondsFiltering = durationFiltering.count();

    int secondsFiltering = millisecondsFiltering / 1000;
    millisecondsFiltering %= 1000;

    int minutesFiltering = secondsFiltering / 60;
    secondsFiltering %= 60;

    //Running time of filtering process

    cout <<  "Duration (Filtering): " << minutesFiltering << " minute(s) " << secondsFiltering << " second(s) " << millisecondsFiltering << " millisecond(s)" << endl;

    cout <<  "Duration (Filtering): " << durationFiltering.count() << endl;

    //Read the secret key

    //PrivateKey<DCRTPoly> sk = readSecretKey("/key-private.txt");

    saveEncryptedResult("/result.txt", filteringResults);

    //Get the result (number of variants matching the query)

    auto startDecryption = high_resolution_clock::now();

    int count = 0;

    for (int i = 0; i < numberOfVariants/blockSize; i++){

        Plaintext plaintextResult = getResult(cc, sk, filteringResults[i]);
        for (int j = 0; j < blockSize; j++){
            if (plaintextResult->GetPackedValue()[j] == 0){
                count++;
            }
        } 
    }  

    auto endDecryption = high_resolution_clock::now();

    auto durationDecryption = duration_cast<milliseconds>(endDecryption - startDecryption);

    int millisecondsDecryption = durationDecryption.count();

    int secondsDecryption = millisecondsDecryption / 1000;
    millisecondsDecryption %= 1000;

    int minutesDecryption = secondsDecryption / 60;
    secondsDecryption %= 60;

    //Running time of filtering process

    cout <<  "Duration (Decryption): " << minutesDecryption << " minute(s) " << secondsDecryption << " second(s) " << millisecondsDecryption << " millisecond(s)" << endl;
    cout <<  "Duration (Decryption): " << durationDecryption.count() << endl;

    // Display the result

    std::cout << "Result: " << count << std::endl;

    return 0;

}
