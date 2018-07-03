//#include "UServerT1V1.h"
//#include "UServerT1V2.h"
//#include "UServerT1V3.h"
//#include "UServerT2V1.h"
#include "UServerT2V2.h"
//#include "UServerT2V3.h"


//#include "UServerV1.h"
#include <ctime>
#include <chrono>
#include <iomanip>
int main() {
    clock_t c_start = clock();
    auto t_start = chrono::high_resolution_clock::now();

    //UServerT1V1 server("127.0.0.1",5001,"127.0.0.1",5002,3);
    // UServerT1V2 server("127.0.0.1",5001,"127.0.0.1",5002,3);
    //UServerT1V3 server("127.0.0.1",5001,"127.0.0.1",5002,3);
    //UServerT2V1 server("127.0.0.1",5001,"127.0.0.1",5002,3);
    UServerT2V2 server("127.0.0.1",5001,"127.0.0.1",5002,3);
    //UServerT2V3 server("127.0.0.1",5001,"127.0.0.1",5002,3);

    std::clock_t c_end = std::clock();
    auto t_end = std::chrono::high_resolution_clock::now();

    std::cout << fixed << setprecision(2) << "CPU time used: "
              << 1000.0 * (c_end-c_start) / CLOCKS_PER_SEC << " ms\n"
              << "Wall clock time passed: "
              << chrono::duration<double, milli>(t_end-t_start).count()
              << " ms"<<endl;
    return 0;
}

