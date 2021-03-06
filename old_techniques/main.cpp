//#include "UServer.h"
#include "UServerV1.h"
//#include "UServerV2.h"
//#include "UServerV3.h"
#include <ctime>
#include <chrono>
#include <iomanip>
int main() {
    clock_t c_start = clock();
    auto t_start = chrono::high_resolution_clock::now();

    //UServer server("127.0.0.1",5001,"127.0.0.1",5002,3);

    UServerV1 server("127.0.0.1",5001,3);
    //UServerV2 server("127.0.0.1",5001,"127.0.0.1",5002,3);
    //UServerV3 server("127.0.0.1",5001,"127.0.0.1",5002,3);

    std::clock_t c_end = std::clock();
    auto t_end = std::chrono::high_resolution_clock::now();

    std::cout << fixed << setprecision(2) << "CPU time used: "
              << 1000.0 * (c_end-c_start) / CLOCKS_PER_SEC << " ms\n"
              << "Wall clock time passed: "
              << chrono::duration<double, milli>(t_end-t_start).count()
              << " ms"<<endl;
    return 0;
}

