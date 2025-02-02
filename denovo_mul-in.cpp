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

Ciphertext<DCRTPoly> filterVariantsDeNovo(std::vector<string> filenames, CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ciphertextNot){

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

    auto ciphertextsXOR_Result_0 = cc->EvalMultMany(ciphertextsXOR_0);
    auto ciphertextsXOR_Result_1 = cc->EvalMultMany(ciphertextsXOR_1);
    auto ciphertextsXOR_Result = cc->EvalAdd(ciphertextsXOR_Result_0, ciphertextsXOR_Result_1);

    return ciphertextsXOR_Result;

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

    omp_set_num_threads(64);


    // Read the cryptocontext and keys

    CryptoContext<DCRTPoly> cc = readCryptoContext("/cryptocontext.txt");
    PublicKey<DCRTPoly> pk = readPublicKey("/key-public.txt");

    readEvalMultKeys(cc);
    readEvalRotationKeys(cc);
    readEvalSumKeys(cc);

    auto ciphertextNot = getCiphertextNot(cc, pk);


    //Get sample filenames

    vector<vector<string>> sampleFilenames = getSampleFilenamesDeNovo();
    

    auto startFiltering = high_resolution_clock::now();

    std::vector<Ciphertext<DCRTPoly>> filteringResults;

    //Filter variants in each block

    #pragma omp parallel for

    for (int i = 0; i < numberOfVariants/blockSize; i++){

        Ciphertext<DCRTPoly> ciphertextsFilteringResult = filterVariantsDeNovo(sampleFilenames[i], cc, ciphertextNot);
        filteringResults.push_back(ciphertextsFilteringResult);

    }

    auto endFiltering = high_resolution_clock::now();

    //Sum filtered variants

    auto startSum = high_resolution_clock::now();

    Ciphertext<DCRTPoly> sumResult;
    Ciphertext<DCRTPoly> result;

    if (filteringResults.size() == 1){

        sumResult = filteringResults[0];

    }else{


        sumResult = sumFilteringResults(cc, filteringResults);
    }

    result = sum(cc, sumResult);

    auto endSum = high_resolution_clock::now();


    auto durationFiltering = duration_cast<milliseconds>(endFiltering - startFiltering);

    int millisecondsFiltering = durationFiltering.count();

    int secondsFiltering = millisecondsFiltering / 1000;
    millisecondsFiltering %= 1000;

    int minutesFiltering = secondsFiltering / 60;
    secondsFiltering %= 60;

    //Running time of filtering process

    cout <<  "Duration (Filtering): " << minutesFiltering << " minute(s) " << secondsFiltering << " second(s) " << millisecondsFiltering << " millisecond(s)" << endl;

    cout <<  "Duration (Filtering): " << durationFiltering.count() << endl;

    auto durationSum = duration_cast<milliseconds>(endSum - startSum);

    int millisecondsSum = durationSum.count();

    int secondsSum = millisecondsSum / 1000;
    millisecondsSum %= 1000;

    int minutesSum = secondsSum / 60;
    secondsSum %= 60;

    cout <<  "Duration (Sum): " << minutesSum << " minute(s) " << secondsSum << " second(s) " << millisecondsSum << " millisecond(s)"<< endl;
    cout <<  "Duration (Sum): " << durationSum.count() << endl;

    //Read the secret key

    PrivateKey<DCRTPoly> sk = readSecretKey("/key-private.txt");

    saveEncryptedResult2("/result.txt", result);

    //Get the result (number of variants matching the query)

    auto startDecryption = high_resolution_clock::now();

    // Decrypt the sum result

    Plaintext plaintextResult = getResult(cc, sk, result);

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

    std::cout << "Result: " << plaintextResult->GetPackedValue()[0] << std::endl;

    return 0;

}
