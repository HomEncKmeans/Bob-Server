//
// Created by george on 16/11/2017.
//

#ifndef USERVER_USERVER_H
#define USERVER_USERVER_H

#include <istream>
#include <cstring>
#include <cstdio>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "userverfhesiutils.h"
#include <utility>
#include <map>
#include <bitset>

using namespace std;
class UServer {
private:
    int k;
    string u_serverIP;
    int u_serverPort;
    int u_serverSocket;
    string t_serverIP;
    int t_serverPort;
    int t_serverSocket;
    int clientSocket;

    FHEcontext *client_context;
    FHESIPubKey *client_pubkey;
    KeySwitchSI *client_SM;
    map<size_t ,bitset<6>> A;
    map<size_t ,Ciphertext> cipherMAP;
    size_t *centroids;

    void socketCreate();
    void socketBind();
    void socketListen();
    void socketAccept();
    void handleRequest(int);
    void receiveEncryptionParamFromClient(int);
    void receiveEncryptedData(int);

public:
    UServer(string,int,string,int,int);
    bool sendStream(ifstream,int);
    bool sendMessage(int,string);
    string receiveMessage(int, int buffersize=64);
    ifstream receiveStream(int,string filename="temp.dat");
    void log(int,string);



};


#endif //USERVER_USERVER_H
