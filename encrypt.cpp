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

int main() {

    generateData();
    generateSamples();

    int multDepth = 2;
    vector<string> fileNames = readParameters("parameters.txt");

    generateCryptoContext(fileNames, multDepth);

}
