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
class UServerV1 {
private:
    // K-means
    //unsigned k;
    map<uint32_t  ,string> cipherMAP;
    map<uint32_t ,vector<Ciphertext>> cipherpoints;
    map<uint32_t ,vector<Ciphertext>> centroids;
    map<uint32_t ,int> centroids_clusters;
    map<int,uint32_t > rev_centroids_clusters;
    map<uint32_t ,uint32_t > cipherIDs;
    unsigned dim;
    unsigned number_of_points;

    // Networking
    string u_serverIP;
    int u_serverPort;
    int u_serverSocket;

    // Cryptography
    FHEcontext *client_context;
    FHESIPubKey *client_pubkey;
    KeySwitchSI *client_SM;

    // Control  Parameters
    bool active;
    bool verbose;
    //Functions
    void socketCreate();
    void socketBind();
    void socketListen();
    void socketAccept();
    void handleRequest(int);
    void receiveEncryptionParamFromClient(int);
    void receiveEncryptedData(int);
    void receiveCentroids(int);
    void sendDistances(int);



    void connectToTServer();
    ifstream distanceToStream(const Ciphertext &);
    void initializeKMToTServer();
    void endKMToTserver();
    ifstream centroidsToStream(const Ciphertext &);


public:
    UServerV1(string,int, bool verbose=true);
    bool sendStream(ifstream,int);
    bool sendMessage(int,string);
    string receiveMessage(int, int buffersize=64);
    ifstream receiveStream(int,string filename="temp.dat");
    void log(int,string);




};


#endif //USERVER_USERVER_H
