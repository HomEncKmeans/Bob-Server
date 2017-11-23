//
// Created by George Sakellariou on 29/09/2017.
//

#include "userverfhesiutils.h"

using namespace std;

Ciphertext FHE_HM(Ciphertext &c1, Ciphertext &c2) {
    Ciphertext distance;
    distance=c2;
    distance*=-1;
    distance+=c1;
    return distance;
}
