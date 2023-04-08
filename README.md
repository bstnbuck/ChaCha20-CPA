# CPA (Correlation Power Analysis) Attack against ChaCha20

> Research work together with [@pwilliv](https://github.com/pwilliv) (https://github.com/pwilliv/ImplAttacksCm). 

For the CPA, the Pearson correlation coefficient is used. Hiding is used as a countermeasure. This combines shuffling and random dummy instructions in one. See the paper for more information

## Requirements
* ChipWhisperer side-channel toolchain (https://chipwhisperer.readthedocs.io/en/latest/index.html#install)
* ChipWhisperer Lite Board

## Usage
> Simply open and start the Jupyter-Notebooks in the ChipWhisperer Environment. 

## Source code
The source code can be found in the `src` folder.
* Jupyter-Notebooks for (automated) Measurement and Attack scenario.
* Source-Code of ChaCha20 in pure C99 + shuffled version (up to 0, 4, 20 additional dummy instructions)
* Example Jupyter-Notebooks (500, 15k, 50k traces)
* ChaCha20 Implementation in Python

## Paper
The paper can be found in German and English in the `paper` folder.

> Thanks to [@shiffthq](https://github.com/shiffthq) (https://github.com/shiffthq/chacha20) for the initial ChaCha20 C Source-Code!