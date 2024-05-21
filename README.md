CKKSEIF - Library of Encrypted Indicator Function
=====================================

This code is based on OpenFHE
* [OpenFHE documentation](https://openfhe-development.readthedocs.io/en/latest/)
* [Design paper for OpenFHE](https://eprint.iacr.org/2022/915)
* [OpenFHE website](https://openfhe.org)

## Installation

cd build
cmake ..
make
./test 

Options:
User can add options to test specific parts of algorithm, as following.

example) 
./test --iteration 8 --indicator --lutsynth

- --iteration x 
set iteration to x

- --indicator
Indicator tests for scaling factor 35, 50

- --anotherindicator
To compare other design choices, we implemented various indicator functions, including Approximate comparison, Sinc approximation, Lagrange Interpolation. 

- --lutsynth
Test for various construction of encrypted LUT, on Z^64 to R^16.

- --embedding
Test for encrypted embedding layer of GloVe6B50d, GloVe42B300d, GPT-2.

- --all
Conduct all of above.