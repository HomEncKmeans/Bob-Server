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

Ciphertext FHE_HM(Ciphertext &c1, Ciphertext &c2);
template <typename T>
void print(const T &message){
    std::cout<<message<<std::endl;
}

#endif