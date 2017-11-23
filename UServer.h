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
#include "Serialization.h"
#include <random>
#include "Ciphertext.h"
#include "unistd.h"

using namespace std;
class UServer {
private:
    // K-means
    unsigned k;
    map<size_t ,bitset<6>> A;
    map<size_t ,bitset<6>> A_r;
    map<size_t ,string> cipherMAP;
    map<size_t ,Ciphertext> cipherpoints;
    map<size_t,Ciphertext> centroids;
    map<size_t,int> centroids_clusters;
    map<int,size_t> rev_centroids_clusters;
    map<size_t,size_t> cipherIDs;
    long neg_coef;
    int max_round;
    int variance_bound;

    // Networking
    string u_serverIP;
    int u_serverPort;
    int u_serverSocket;
    string t_serverIP;
    int t_serverPort;
    int t_serverSocket;
    int clientSocket;

    // Cryptography
    FHEcontext *client_context;
    FHESIPubKey *client_pubkey;
    KeySwitchSI *client_SM;

    void socketCreate();
    void socketBind();
    void socketListen();
    void socketAccept();
    void handleRequest(int);
    void receiveEncryptionParamFromClient(int);
    void receiveEncryptedData(int);
    void connectToTServer();
    ifstream distanceToStream(const Ciphertext &);
    void initializeClusters();
    void initializeCentroids();
    long calculateVariance();
    void swapA();
    void initializeKMToTServer();

public:
    UServer(string,int,string,int,unsigned ,int max_round=5,int variance_bound=0);
    bool sendStream(ifstream,int);
    bool sendMessage(int,string);
    string receiveMessage(int, int buffersize=64);
    ifstream receiveStream(int,string filename="temp.dat");
    void log(int,string);




};


#endif //USERVER_USERVER_H
