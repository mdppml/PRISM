#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "saveData.h"
#include "readData.h"
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

std::vector<Ciphertext<DCRTPoly>> filterVariantsDeNovo(std::vector<string> filenames, CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ciphertextNot, Ciphertext<DCRTPoly> ciphertextNumSamples){

    std::vector<Ciphertext<DCRTPoly>> ciphertextsVec;
    
    std::vector<Ciphertext<DCRTPoly>> ciphertextsXOR_0;
    std::vector<Ciphertext<DCRTPoly>> ciphertextsXOR_1;

    for (int j = 0; j < numberOfSamples*2; j++){

        auto ciphertextRead = readEncryptedData(filenames[j]);

        Ciphertext<lbcrypto::DCRTPoly> ciphertextResult_0;

        if (j < numberOfSamples){

            ciphertextResult_0 = ciphertextRead;

            if (j % 2 == 0){
                ciphertextsXOR_0.push_back(ciphertextResult_0);
            }else{
                ciphertextsXOR_1.push_back(ciphertextResult_0);
            }
      
        }else{

            ciphertextResult_0 = cc->EvalSub(ciphertextNot, ciphertextRead);

            if (j % 2 == 0){
                ciphertextsXOR_0.push_back(ciphertextResult_0);
            }else{
                ciphertextsXOR_1.push_back(ciphertextResult_0);
            }
        }
    }

    auto ciphertextsXOR_Result_0 = cc->EvalAddMany(ciphertextsXOR_0);
    auto ciphertextsXOR_Result_1 = cc->EvalAddMany(ciphertextsXOR_1);
    auto ciphertext_Result_0 = cc->EvalSub(ciphertextsXOR_Result_0, ciphertextNumSamples);
    auto ciphertext_Result_1= cc->EvalSub(ciphertextsXOR_Result_1, ciphertextNumSamples);

    ciphertextsVec.push_back(ciphertext_Result_0);
    ciphertextsVec.push_back(ciphertext_Result_1);
    

    return ciphertextsVec;

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

    omp_set_num_threads(4);

    // Read the cryptocontext and keys

    CryptoContext<DCRTPoly> cc = readCryptoContext("/cryptocontext.txt");
    PublicKey<DCRTPoly> pk = readPublicKey("/key-public.txt");

    readEvalMultKeys(cc);
    readEvalRotationKeys(cc);
    readEvalSumKeys(cc);

    auto ciphertextNot = getCiphertextNot(cc, pk);

    auto ciphertextNumSamples = getCiphertextNumSamplesDeNovo(cc,pk);

    //Get random vector 

    auto randomCiphertext = getRandomVector(cc, pk, blockSize, 1, 1000);

    //Get sample filenames

    vector<vector<string>> sampleFilenames = getSampleFilenamesDeNovo();

    auto startFiltering = high_resolution_clock::now();

    std::vector<Ciphertext<DCRTPoly>> filteringResults;

    //Filter variants in each block

    #pragma omp parallel for

    for (int i = 0; i < numberOfVariants/blockSize; i++){

        std::vector<Ciphertext<DCRTPoly>> ciphertextsFilteringResult = filterVariantsDeNovo(sampleFilenames[i], cc, ciphertextNot, ciphertextNumSamples);
        auto ciphertextFilteringMulResult = cc->EvalMult(ciphertextsFilteringResult[0], ciphertextsFilteringResult[1]);
        auto ciphertextsFilteringResultRandom = cc->EvalMult(ciphertextFilteringMulResult, randomCiphertext); 
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

    PrivateKey<DCRTPoly> sk = readSecretKey("/key-private.txt");

    saveEncryptedResult("/result.txt", filteringResults);

    //Get the result (number of variants matching the de novo case)

    auto startDecryption = high_resolution_clock::now();

    int count = 0;

    for (int i = 0; i < numberOfVariants/blockSize; i = i + 1){

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
