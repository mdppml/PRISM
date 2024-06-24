# Privacy Preserving Rare Disease Analysis with Fully Homomorphic Encryption

OpenFHE Library Installation:

<https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html>

## Executable Files

- main.cpp: This file contains the method that uses fewer multiplication operations for recessive and dominant inheritance models.

- main2.cpp: This file contains the method that uses more multiplication operations for recessive and dominant inheritance models.

- denovo.cpp: This file contains the method that uses fewer multiplication operations for the Denovo inheritance model.

- denovo2.cpp: This file contains the method that uses more multiplication operations for the Denovo inheritance model.

- encrypt.cpp: This file generates and encrypts the sample data for experiments.

## Experiments

For experiments, the number of samples and variants can be determined using numberOfSamples and numberOfVariants variables in saveData.h file.

Also, the number of threads can be determined using omp_set_num_threads(1); in main.cpp, main2.cpp, denovo.cpp and denovo2.cpp files.

The code can be executed using the following commands:

cd build

cmake -DWITH_INTEL_HEXL=ON DWITH_NTL=ON -DWITH_TCM=ON -DWITH_OPENMP=ON  ..

make

The encrypt.cpp file should be executed to generate and encrypt the sample data for experiments using the following command (The multDepth variable should be set 1 (for main.cpp and denovo.cpp) or 6 (for main2.cpp and denovo2.cpp) in encrypt.cpp file.): 

./encrypt

The main.cpp, main2.cpp, denovo.cpp and denovo2.cpp files can be executed to perform the variant filtering process for encrypted samples using the following commands:

./main

./main2

./denovo

./denovo2
