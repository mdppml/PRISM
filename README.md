# Privacy Preserving Rare Disease Analysis with Fully Homomorphic Encryption

OpenFHE Library Installation:

<https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html>

The code can be executed using the following commands:

cd build

cmake -DWITH_INTEL_HEXL=ON DWITH_NTL=ON -DWITH_TCM=ON -DWITH_OPENMP=ON  ..

make

The encrypt.cpp file should be executed to generate and encrypt the sample data for experiments using the following command.

./encrypt

The main.cpp file should be executed to perform the variant filtering process for encrypted samples using the following command.

./main

The number of samples and variants can be determined using numberOfSamples and numberOfVariants variables in saveData.h file for experiments. 
Also, the number of threads can be determined using omp_set_num_threads(1); in main.cpp file.
