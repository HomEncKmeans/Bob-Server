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
#include "chrono"
#include "ctime"
#include "iomanip"

Ciphertext FHE_HM(Ciphertext &c1, Ciphertext &c2);
void timeCalulator(const clock_t &c_start, const chrono::high_resolution_clock::time_point &t_start);
Ciphertext euclideanDistance(vector<Ciphertext> &cpoint1, vector<Ciphertext> &cpoint2, KeySwitchSI &keySwitchSI);
Ciphertext euclideanDistanceP(Ciphertext &c1, Ciphertext &c2, KeySwitchSI &keySwitchSI);
vector<Ciphertext> FHE_HM1(vector<Ciphertext> &cpoint1, vector<Ciphertext> &cpoint2);


template <typename T>
void print(const T &message){
    std::cout<<message<<std::endl;
}

#endif