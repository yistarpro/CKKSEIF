CKKSEIF - Library of Encrypted Indicator Function on CKKS scheme
=====================================

This repository is implementation of Encrypted Indicator Function and its application on NLP, on following works:


* [KPLC24] Jae-yun Kim, Saerom Park, Joohee Lee, Jung Hee Cheon: Privacy-preserving embedding via look-up table evaluation with fully homomorphic encryption. Forty-first International Conference on Machine Learning, 2024. [Link]

```
@inproceedings{2024embedding,
  title={Privacy-preserving embedding via look-up table evaluation with fully homomorphic encryption},
  author={Kim, Jae-yun and Park, Saerom and Lee, Joohee and Cheon, Jung Hee},
  booktitle={Proceedings of the 41st International Conference on Machine Learning},
  pages={24437--24457},
  year={2024}
}
```

[Link]:https://openreview.net/forum?id=apxON2uH4N



* [KYCP24] Jae-yun Kim, Jieun Yun, Jung Hee Cheon, Saerom Park: Efficient Privacy-Preserving Counting Method with Homomorphic Encryption. 27th International Conference on Information Security and Cryptology, 2024.


## Installation

This code is based on OpenFHE
* [OpenFHE documentation](https://openfhe-development.readthedocs.io/en/latest/)
* [Design paper for OpenFHE](https://eprint.iacr.org/2022/915)
* [OpenFHE website](https://openfhe.org)

Note our implementation is on version 1.1.4

After installing OpenFHE, get data from following link:

* https://drive.google.com/file/d/17YVk3uR_Q25j0ebJzyrblDupi1aMtwhz/view?usp=sharing

These data contains compressed embedding, indices for the embedding, parameter of logistic regression and some documents for test input. They are obtained by operating following repository:

* https://github.com/yistarpro/compositional_code_learning

Put the files in data folder, then operate following on "CKKSEIF" directory:

* cd build
* cmake ..
* make
* ./test 

## Options for Various Tests
User can add options to test specific parts of algorithm, as following.

* example:
* ./test --iteration 8 --indicator --lutsynth

- --iteration x 
set the number of iteration to x

# Tests for Encrypted Embedding Layer

- --indicator
Indicator tests for scaling factor 35, 50

- --anotherindicator
To compare other design choices, we implemented various indicator functions, including approximate comparison, sinc approximation, Lagrange interpolation. 

- --lutsynth
Tests for various construction of encrypted LUT, on Z^64 to R^16.

- --embedding
Tests for encrypted embedding layer of GloVe6B50d, GloVe42B300d, GPT-2.

- --logreg
Tests for encrypted logistic regression on GloVe6B50d, GloVe42B300d

- --emball
Conduct all of above, which are all tests from [KPLC24].


# Tests for Encrypted Counting Algorithm

- --count
Tests for various construction of encrypted counting algortihm, on vocabulary size 256 and 256 arrays of size 256.

- --paralcount
Tests for various construction of parallelized encrypted counting algortihm, on vocabulary size 256 and various number of arrays of size 256.

- --ngram
Tests for 2 / 3 -gram on vocabulary size 64.

- --info
Tests for E2EE information retrieval algorithm on Amazon Food Review Dataset. 

- --countall
Conduct all of above, which are all tests from [KYCP24].

## Note on Structure of the Library

# Files

- algorithms: collection of our algorithms specified in the papers.

- embeddings: this code loads models for deep-learning based NLP tasks.

- test: main function for varous test.

- testcode: code containg test pipeline of our algorithms.

- utils: various algorithms for test, including reading/writing of data, random number generation, and precision estimation.

# Parameters

Our CKKS parameter is specified on the papers, but the batch size is the same over all implementations: 2^16.

Most of the algorithms utilize coded input (Discrete Vector), and following are the major variables specifying  domain / codomain of the algorithms.

- bound: size of domain, 'p' in the papers.
- numcode: number of codebook, 'l' in the papers.
- outputdimension: dimension of embedding layer.
