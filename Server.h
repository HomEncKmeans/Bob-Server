//
// Created by george on 7/11/2017.
//

#ifndef AUTH_THESIS_FHE_SI_SERVER_H
#define AUTH_THESIS_FHE_SI_SERVER_H

#include <iostream>
#include <cstring>
#include <cstdio>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "FHE-SI.h"
#include "userverfhesiutils.h"
using namespace std;

class Server {

private:
    string serverIp;
    int serverPort;
    int masterSocket;
    string addressT;
    int portT;
    int socketT;
    bool GMODE=true; // general operational mode server listen for the first request
    bool PMODE=false; // server initializes cryptographic parameters
    bool DMODE=false; // server receives data
    bool KMODE1=false; // server classifies the points
    bool KMODE2=false; // server calculates the new centroids
    int protocol_step=0; // counts the protocol step


    void defineMode(bool,bool,bool,bool,bool);
    void socketCreate();

    void socketBind();

    void socketListen();

    void socketAccept();

    void handleRequest(int);


public:
    Server(string, int,string, int);

    void sendData(int, string);

    void log(int, string);


    ifstream readStream(int);
    string readData(int,int);


};


#endif //AUTH_THESIS_FHE_SI_SERVER_H
