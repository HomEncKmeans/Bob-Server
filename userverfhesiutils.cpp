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

void timeCalulator(const clock_t &c_start, const chrono::high_resolution_clock::time_point &t_start) {
    std::clock_t c_end = std::clock();
    auto t_end = std::chrono::high_resolution_clock::now();
    std::cout << fixed << setprecision(2) << "CPU time used: "
              << 1000.0 * (c_end-c_start) / CLOCKS_PER_SEC << " ms\n"
              << "Wall clock time passed: "
              << chrono::duration<double, milli>(t_end-t_start).count()
              << " ms"<<endl;
}

Ciphertext euclideanDistance(vector<Ciphertext> &cpoint1, vector<Ciphertext> &cpoint2, KeySwitchSI &keySwitchSI) {
    Ciphertext total;
    unsigned long dimension=cpoint1.size();
    total=euclideanDistanceP(cpoint1[0],cpoint2[0],keySwitchSI);
    for (int i = 1; i <dimension ; ++i) {
        Ciphertext coefficient_distance;
        coefficient_distance=euclideanDistanceP(cpoint1[i],cpoint2[i],keySwitchSI);
        total+=coefficient_distance;
    }
    return total;

}

Ciphertext euclideanDistanceP(Ciphertext &c1, Ciphertext &c2, KeySwitchSI &keySwitchSI) {
    Ciphertext total;
    Ciphertext semi_total;
    semi_total=c2;
    semi_total*=-1;
    semi_total+=c1;
    total=semi_total;
    total*=semi_total;
    total.ScaleDown();
    keySwitchSI.ApplyKeySwitch(total);
    return total;
}

