//
// Created by George Sakellariou on 29/09/2017.
//

#ifndef USERVER_USERVERFHESIUTILS_H
#define USERVER_USERVERFHESIUTILS_H

#include <string>
#include "FHEContext.h"
#include "Matrix.h"
#include <string>
#include <iostream>
#include <fstream>
#include "FHE-SI.h"
#include <bitset>
#include "ZZ_pX.h"
#include "Ciphertext.h"
void readData(const string filename);
unsigned calculatelogQ(unsigned const &p,unsigned xi, unsigned &dim );
unsigned calculateXI(unsigned const &p,unsigned size, unsigned &dim);
bool LoadData(Matrix<ZZ> &rawData, vector<ZZ> &labels, unsigned &dim, const string &filename);
bool LoadDataPolyX(vector<ZZ_pX> &rawData, vector<ZZ_p> &labels, unsigned &dim, const string &filename, FHEcontext &context);
void savePublicKey(const FHESIPubKey &fhesiPubKey, const string &filename);
void saveSwitchedKey(const KeySwitchSI &keySwitchSI, const string &filename);
void saveSecretKey(const FHESISecKey &fhesiSecKey, const string &filename);
ZZ_p extraxtHM(const ZZ_pX &poly);
ZZ_pX numbertoZZ_pX(long &number, FHEcontext &econtext);
unsigned long MSB(ZZ_pX &numberPoly,long vector_length=64);
ZZ_pX MSB_poly(ZZ_pX &numberPoly);
long ptToNumber(Plaintext &ptxt);
Ciphertext FHE_Sub(Ciphertext &c1, Ciphertext &c2, Ciphertext &negCoef,KeySwitchSI &keySwitchSI);
Plaintext binaryFHEAddTransformation(Plaintext &plaintext);
unsigned long MSB(long &number);
Ciphertext FHE_MSB(Ciphertext &c1, Ciphertext &c2, Ciphertext &negCoef, Ciphertext &eCoef, KeySwitchSI &keySwitchSI);
Ciphertext FHE_MAX(Ciphertext &c1, Ciphertext &c2, Ciphertext &posCoef,Ciphertext &negCoef, Ciphertext &eCoef, KeySwitchSI &keySwitchSI);

template <typename T>
void print(const T &message){
    std::cout<<message<<std::endl;
}


#endif