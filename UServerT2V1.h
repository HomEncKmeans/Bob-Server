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
#include "old_techniques/userverfhesiutils.h"
#include <utility>
#include <map>
#include <bitset>
#include "Serialization.h"
#include <random>
#include "Ciphertext.h"
#include "unistd.h"

using namespace std;
class UServerT2V1 {
private:
    // K-means
    unsigned k;
    map<uint32_t ,vector<Ciphertext>> A;
    map<uint32_t ,vector<Ciphertext>> A_r;
    map<uint32_t ,string> cipherMAP;
    map<uint32_t ,Ciphertext> cipherpoints;
    map<uint32_t,Ciphertext> centroids;
    map<uint32_t,int> centroids_clusters;
    map<int,uint32_t> rev_centroids_clusters;
    map<uint32_t,uint32_t> cipherIDs;
    map<uint32_t,Ciphertext> clusters_size;
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
    void initializeClustersandCentroids();
    void swapA();
    void initializeKMToTServer();
    void endKMToTserver();
    ifstream centroidToStream(const Ciphertext &);
    ifstream clusterSizeToStream(const Ciphertext &);
    ifstream resultToStream(const Ciphertext &);

    void resultsToKClient();

public:
    UServerT2V1(string,int,string,int,unsigned ,int max_round=5,int variance_bound=0);
    bool sendStream(ifstream,int);
    bool sendMessage(int,string);
    string receiveMessage(int, int buffersize=64);
    ifstream receiveStream(int,string filename="temp.dat");
    void log(int,string);




};


#endif
