# PRISM: Privacy-preserving Rare Disease Analysis using Fully Homomorphic Encryption

## Requirements

- OpenFHE Library Installation:

<https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html>

## Executable Files

- recessive_dominant_add-in.cpp: This file contains the method that uses fewer multiplication operations for recessive and dominant inheritance models.

- recessive_dominant_mul-in.cpp: This file contains the method that uses more multiplication operations for recessive and dominant inheritance models.

- denovo_add-in.cpp: This file contains the method that uses fewer multiplication operations for the Denovo inheritance model.

- denovo_mul-in.cpp: This file contains the method that uses more multiplication operations for the Denovo inheritance model.

- encrypt.cpp: This file generates and encrypts the sample data for experiments.

## Experiments

- For experiments, the number of samples and variants can be determined using numberOfSamples and numberOfVariants variables in saveData.h file.

- Also, the number of threads can be determined using omp_set_num_threads(1); in recessive_dominant_add-in.cpp, recessive_dominant_mul-in.cpp, denovo_add-in.cpp and denovo_mul-in.cpp files.

- The code can be configured and compiled using the following commands:
- 
```
cd build
cmake -DWITH_INTEL_HEXL=ON DWITH_NTL=ON -DWITH_TCM=ON -DWITH_OPENMP=ON  ..
make
```
- The encrypt.cpp file should be executed to generate and encrypt the sample data for experiments using the following command (The multDepth variable should be set 2 (for recessive_dominant_add-in.cpp and denovo_add-in.cpp) or 12 (for recessive_dominant_mul-in.cpp and denovo_mul-in.cpp) in encrypt.cpp file.): 
```
./encrypt
```
- The recessive_dominant_add-in.cpp, recessive_dominant_mul-in.cpp, denovo_add-in.cpp and denovo_mul-in.cpp files can be executed to perform the variant filtering process for encrypted samples using the following commands:
```
./recessive_dominant_add-in.cpp
./recessive_dominant_mul-in.cpp
./denovo_add-in.cpp
./denovo_mul-in.cpp
```
