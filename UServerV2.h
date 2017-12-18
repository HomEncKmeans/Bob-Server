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
class UServerV2 {
private:
    // K-means
    unsigned k;
    map<uint32_t ,bitset<6>> A;
    map<uint32_t ,bitset<6>> A_r;
    map<uint32_t ,string> cipherMAP;
    map<uint32_t ,vector<Ciphertext>> cipherpoints;
    map<uint32_t,vector<Ciphertext>> centroids;
    map<uint32_t,int> centroids_clusters;
    map<int,uint32_t> rev_centroids_clusters;
    map<uint32_t,uint32_t> cipherIDs;
    int max_round;
    int variance_bound;
    unsigned dim;
    unsigned number_of_points;
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
    void endKMToTserver();
    ifstream centroidsCoefToStream(const Ciphertext &);
    void resultsToKClient();

public:
    UServerV2(string,int,string,int,unsigned ,int max_round=5,int variance_bound=0);
    bool sendStream(ifstream,int);
    bool sendMessage(int,string);
    string receiveMessage(int, int buffersize=64);
    ifstream receiveStream(int,string filename="temp.dat");
    void log(int,string);




};


#endif //UServerV2_UServerV2_H
