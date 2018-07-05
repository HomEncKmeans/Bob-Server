//
// Created by george on 16/11/2017.
//

#include "UServerT2V1.h"


UServerT2V1::UServerT2V1(string u_serverIP, int u_serverPort, string t_serverIP, int t_serverPort, unsigned k,
                     int max_round,
                     int variance_bound) {
    this->k = k;
    this->max_round = max_round;
    this->variance_bound = variance_bound;
    this->u_serverIP = move(u_serverIP);
    this->u_serverPort = u_serverPort;
    this->t_serverIP = move(t_serverIP);
    this->t_serverPort = t_serverPort;
    this->t_serverSocket = -1;
    print("UNTRUSTED SERVER");
    this->socketCreate();
    this->socketBind();
    this->socketListen();
    this->socketAccept();
    print("CLIENT ENCRYPTION PARAMETERS");
    ifstream contextfile("context.dat");
    FHEcontext fhEcontext(contextfile);
    this->client_context = &fhEcontext;
    activeContext = &fhEcontext;
    ifstream pkC("pkC.dat");
    FHESIPubKey fhesiPubKey(fhEcontext);
    fhesiPubKey.Import(pkC);
    this->client_pubkey = &fhesiPubKey;
    ifstream smC("smC.dat");
    KeySwitchSI keySwitchSI(fhEcontext);
    keySwitchSI.Import(smC);
    this->client_SM = &keySwitchSI;
    print("CONTEXT");
    print(fhEcontext);
    print("CLIENT PUBLIC KEY");
    print(fhesiPubKey);
    print("CLIENT - UServerT2V1 SWITCH MATRIX ");
    print(keySwitchSI);
    this->socketAccept();
    print("K-MEANS-INITIALIZATION");
    this->initializeKMToTServer();
    this->initializeClustersandCentroids();
    print("END OF K-MEANS INITIALIZATION");
    print("----------------------------------");
    print("STARTING K-MEANS ROUNDS");
    int r = 0;
    while (r < this->max_round) {
        print("ROUND: " + to_string(r));
        for (auto &iter:this->A_r) {
            this->connectToTServer();
            this->sendMessage(this->t_serverSocket, "U-DP");
            string message = this->receiveMessage(this->t_serverSocket, 7);
            if (message != "T-READY") {
                perror("ERROR IN PROTOCOL 5-STEP 1");
                return;
            }
            for (int i = 0; i < this->k; i++) {
                auto cluster_index = static_cast<uint32_t>(i);
                if (0 > send(this->t_serverSocket, &cluster_index, sizeof(uint32_t), 0)) {
                    perror("SEND CLUSTER INDEX FAILED.");
                    return;
                }
                string message1 = this->receiveMessage(this->t_serverSocket, 13);
                if (message1 != "T-RECEIVED-CI") {
                    perror("ERROR IN PROTOCOL 5-STEP 2");
                    return;
                }
                Ciphertext distance;
                print(iter.first);
                print(this->rev_centroids_clusters[i]);
                distance = FHE_HM(this->cipherpoints[iter.first], this->centroids[this->rev_centroids_clusters[i]]);
                this->sendStream(this->distanceToStream(distance), this->t_serverSocket);
                string message2 = this->receiveMessage(this->t_serverSocket, 12);
                if (message2 != "T-D-RECEIVED") {
                    perror("ERROR IN PROTOCOL 5-STEP 3");
                    return;
                }
            }
            this->sendMessage(this->t_serverSocket, "U-R-I");
            vector<Ciphertext> classificationVec;
            for(unsigned t=0;t<this->k;t++){
                Ciphertext clusterCoef(*this->client_pubkey);
                this->receiveStream(this->t_serverSocket, to_string(t) + "-clusterindex.dat");
                ifstream in(to_string(t) + "-clusterindex.dat");
                Import(in, clusterCoef);
                classificationVec.push_back(clusterCoef);
                this->sendMessage(this->t_serverSocket,"U-R-E-I");
            }

            iter.second = classificationVec;
            this->sendMessage(this->t_serverSocket, "U-RECEIVED-I");
            close(this->t_serverSocket);
            this->t_serverSocket = -1;
        }

        r++;
        print(r);
        this->swapA();
        if (r < this->max_round) {
            print("CREATE NEW CENTROIDS");
            this->sendMessage(this->clientSocket, "U-NC");
            string message3 = this->receiveMessage(this->clientSocket, 10);
            if (message3 != "C-NC-READY") {
                perror("ERROR IN PROTOCOL 6-STEP 1");
                return;
            }
            this->centroids_clusters.clear();
            this->centroids.clear();
            //compute  clusters size
            ZZ_pX sumbase1;
            SetCoeff(sumbase1, 0, 0);
            Plaintext sumbasePlain1(*this->client_context, sumbase1);
            Ciphertext sumbaseCipher1(*this->client_pubkey);
            this->client_pubkey->Encrypt(sumbaseCipher1, sumbasePlain1);
            for (unsigned i=0; i<this->k;i++){
                Ciphertext cluster_size=sumbaseCipher1;
                for(auto &iter:this->A){
                    cluster_size+=this->A[iter.first][i];

                    this->clusters_size[i]=cluster_size;
                }
            }


            for (unsigned i = 0; i < this->k; i++) {
                uint32_t centroid_index = i;
                if (0 > send(this->clientSocket, &centroid_index, sizeof(uint32_t), 0)) {
                    perror("SEND INDEX FAILED.");
                    return;
                }
                string message4 = this->receiveMessage(this->clientSocket, 13);
                if (message4 != "C-RECEIVED-CI") {
                    perror("ERROR IN PROTOCOL 6-STEP 2");
                    return;
                }
                //print(this->clusters_size[i]);
                this->sendStream(this->clusterSizeToStream(this->clusters_size[i]), this->clientSocket);
                string message5 = this->receiveMessage(this->clientSocket, 13);
                if (message5 != "C-RECEIVED-CS") {
                    perror("ERROR IN PROTOCOL 6-STEP 3");
                    return;
                }
                Ciphertext centroid;
                ZZ_pX sumbase;
                SetCoeff(sumbase, 0, 0);
                Plaintext sumbasePlain(*this->client_context, sumbase);
                Ciphertext sumbaseCipher(*this->client_pubkey);
                this->client_pubkey->Encrypt(sumbaseCipher, sumbasePlain);
                Ciphertext total_of_coef=sumbaseCipher;
                for(auto &iter:this->A){
                    Ciphertext helpcipher;
                    helpcipher=this->cipherpoints[iter.first];
                    helpcipher*=this->A[iter.first][i];
                    helpcipher.ScaleDown();
                    this->client_SM->ApplyKeySwitch(helpcipher);
                    total_of_coef+=helpcipher;
                }
                this->sendStream(this->centroidToStream(total_of_coef), this->clientSocket);
                string message7 = this->receiveMessage(this->clientSocket, 12);
                if (message7 != "C-RECEIVED-C") {
                    perror("ERROR IN PROTOCOL 6-STEP 4");
                    return;
                }
                Ciphertext centroid_updated(*this->client_pubkey);
                this->receiveStream(this->clientSocket, to_string(i) + "-centroid.dat");
                ifstream in(to_string(i) + "-centroid.dat");
                Import(in, centroid_updated);
                //this->sendMessage(this->clientSocket, "U-R-COEF");
                srand(static_cast<unsigned int>(time(NULL)));
                uint32_t identifier;
                identifier = static_cast<uint32_t>(rand());
                this->rev_centroids_clusters[i] = identifier;
                this->centroids_clusters[identifier] = i;
                this->centroids[identifier] = centroid_updated;
                this->sendMessage(this->clientSocket, "U-NC-RECEIVED");
            }
            this->sendMessage(this->clientSocket, "U-C-UPDATED");
            string message8 = this->receiveMessage(this->clientSocket, 7);
            if (message8 != "C-READY") {
                perror("ERROR IN PROTOCOL 6-STEP 5");
                return;
            }
            //close(this->t_serverSocket);
            //this->t_serverSocket = -1;
        }

    }
    this->endKMToTserver();
    print("UServer send Results to KClient");
    this->resultsToKClient();
    print("END-OF-KMEANS");
    //this->socketAccept();

}

void UServerT2V1::socketCreate() {
    this->u_serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (this->u_serverSocket < 0) {
        perror("ERROR IN SOCKET CREATION");
        exit(1);
    } else {
        int opt = 1;
        setsockopt(this->u_serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        string message = "Socket created successfully. File descriptor: " + to_string(this->u_serverSocket);
        print(message);
    }

}

void UServerT2V1::socketBind() {
    struct sockaddr_in u_serverAddress;
    u_serverAddress.sin_family = AF_INET;
    u_serverAddress.sin_port = htons(static_cast<uint16_t>(this->u_serverPort));
    u_serverAddress.sin_addr.s_addr = inet_addr(this->u_serverIP.data());
    if (bind(this->u_serverSocket, (sockaddr *) &u_serverAddress, sizeof(u_serverAddress)) < 0) {
        perror("BIND ERROR");
        exit(1);
    } else {
        string message = "Socket bound successfully to :[" + u_serverIP + ":" + to_string(this->u_serverPort) + "]";
        print(message);
    }

}

void UServerT2V1::socketListen() {
    listen(this->u_serverSocket, 5);
    print("Server is listening...");

}

void UServerT2V1::socketAccept() {
    int socketFD;
    socketFD = accept(this->u_serverSocket, NULL, NULL);
    if (socketFD < 0) {
        perror("SOCKET ACCEPT ERROR");
    } else {
        print("CLIENT_CONNECTED");
        this->handleRequest(socketFD);
    }

}

void UServerT2V1::handleRequest(int socketFD) {
    string message = this->receiveMessage(socketFD, 4);
    if (message == "C-PK") {
        this->receiveEncryptionParamFromClient(socketFD);
    } else if (message == "C-DA") {
        this->clientSocket = socketFD;
        this->receiveEncryptedData(socketFD);
    } else {
        perror("ERROR IN PROTOCOL INITIALIZATION");
        return;
    }

}

bool UServerT2V1::sendStream(ifstream data, int socket) {
    uint32_t CHUNK_SIZE = 10000;
    streampos begin, end;
    begin = data.tellg();
    data.seekg(0, ios::end);
    end = data.tellg();
    streampos size = end - begin;
    uint32_t sizek;
    sizek = static_cast<uint32_t>(size);
    data.seekg(0, std::ios::beg);
    auto *memblock = new char[sizek];
    data.read(memblock, sizek);
    data.close();
    htonl(sizek);
    if (0 > send(socket, &sizek, sizeof(uint32_t), 0)) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socket, "<--- " + to_string(sizek));
        if (this->receiveMessage(socket, 7) == "SIZE-OK") {
            auto *buffer = new char[CHUNK_SIZE];
            uint32_t beginmem = 0;
            uint32_t endmem = 0;
            uint32_t num_of_blocks = sizek / CHUNK_SIZE;
            uint32_t rounds = 0;
            while (rounds <= num_of_blocks) {
                if (rounds == num_of_blocks) {
                    uint32_t rest = sizek - (num_of_blocks) * CHUNK_SIZE;
                    endmem += rest;
                    copy(memblock + beginmem, memblock + endmem, buffer);
                    ssize_t r = (send(socket, buffer, rest, 0));
                    rounds++;
                    if (r < 0) {
                        perror("SEND FAILED.");
                        return false;
                    }
                } else {
                    endmem += CHUNK_SIZE;
                    copy(memblock + beginmem, memblock + endmem, buffer);
                    beginmem = endmem;
                    ssize_t r = (send(socket, buffer, 10000, 0));
                    rounds++;
                    if (r < 0) {
                        perror("SEND FAILED.");
                        return false;
                    }
                }
            }
            return true;

        } else {
            perror("SEND SIZE ERROR");
            return false;
        }
    }
}

bool UServerT2V1::sendMessage(int socketFD, string message) {
    if (send(socketFD, message.c_str(), strlen(message.c_str()), 0) < 0) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socketFD, "<--- " + message);
        return true;
    }
}

string UServerT2V1::receiveMessage(int socketFD, int buffersize) {
    char buffer[buffersize];
    string message;
    if (recv(socketFD, buffer, static_cast<size_t>(buffersize), 0) < 0) {
        perror("RECEIVE FAILED");
    }
    message = buffer;
    message.erase(static_cast<unsigned long>(buffersize));
    this->log(socketFD, "---> " + message);
    return message;
}

ifstream UServerT2V1::receiveStream(int socketFD, string filename) {
    uint32_t size;
    auto *data = (char *) &size;
    if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE SIZE ERROR");
    }

    ntohl(size);
    this->log(socketFD, "--> SIZE: " + to_string(size));
    this->sendMessage(socketFD, "SIZE-OK");

    auto *memblock = new char[size];
    ssize_t expected_data=size;
    ssize_t received_data=0;
    while(received_data<expected_data){
        ssize_t data_fd=recv(socketFD, memblock+received_data, 10000, 0);
        received_data +=data_fd;

    }
    print(received_data);

    if (received_data!=expected_data ) {
        perror("RECEIVE STREAM ERROR");
        exit(1);
    }

    ofstream temp(filename, ios::out | ios::binary);
    temp.write(memblock, size);
    temp.close();
    return ifstream(filename);
}

void UServerT2V1::log(int socket, string message) {
    sockaddr address;
    socklen_t addressLength;
    sockaddr_in *addressInternet;
    string ip;
    int port;
    getpeername(socket, &address, &addressLength);
    addressInternet = (struct sockaddr_in *) &address;
    ip = inet_ntoa(addressInternet->sin_addr);
    port = addressInternet->sin_port;
    string msg = "[" + ip + ":" + to_string(port) + "] " + message;
    print(msg);
}

void UServerT2V1::receiveEncryptionParamFromClient(int socketFD) {
    this->sendMessage(socketFD, "U-PK-READY");
    this->receiveStream(socketFD, "pkC.dat");
    this->sendMessage(socketFD, "U-PK-RECEIVED");
    string message = this->receiveMessage(socketFD, 4);
    if (message != "C-SM") {
        perror("ERROR IN PROTOCOL 1-STEP 2");
        return;
    }
    this->sendMessage(socketFD, "U-SM-READY");
    this->receiveStream(socketFD, "smC.dat");
    this->sendMessage(socketFD, "U-SM-RECEIVED");
    string message1 = this->receiveMessage(socketFD, 9);
    if (message1 != "C-CONTEXT") {
        perror("ERROR IN PROTOCOL 2-STEP 4");
        return;
    }
    this->sendMessage(socketFD, "U-C-READY");
    this->receiveStream(socketFD, "context.dat");
    this->sendMessage(socketFD, "U-C-RECEIVED");

    print("PROTOCOL 1 COMPLETED");


}

void UServerT2V1::receiveEncryptedData(int socketFD) {
    this->sendMessage(socketFD, "U-DATA-READY");
    uint32_t numberofpoints;
    auto *data2 = (char *) &numberofpoints;
    if (recv(socketFD, data2, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 3");
    }
    ntohl(numberofpoints);
    this->log(socketFD, "--> Number of Points: " + to_string(numberofpoints));
    this->number_of_points = numberofpoints;
    this->sendMessage(socketFD, "U-N-RECEIVED");
    for (unsigned i = 0; i < this->number_of_points; i++) {
        string message = this->receiveMessage(socketFD, 8);
        if (message != "C-DATA-P") {
            perror("ERROR IN PROTOCOL 3.1-STEP 4");
            return;
        }
        this->sendMessage(socketFD, "U-DATA-P-READY");

        uint32_t identifier;
        auto *data = (char *) &identifier;
        if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
            perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 5");
        }
        ntohl(identifier);
        this->sendMessage(socketFD, "U-P-I-RECEIVED");
        Ciphertext encrypted_point(*this->client_pubkey);
        string filename = "point_" + to_string(i) + ".dat";
        ifstream cipher = this->receiveStream(socketFD, filename);
        ifstream in(filename);
        Import(in, encrypted_point);
        this->cipherpoints[identifier] = encrypted_point;
        this->sendMessage(socketFD, "U-DATA-P-RECEIVED");

        ZZ_pX dataindexpX;
        SetCoeff(dataindexpX, 0, 0);
        Plaintext clusterInd(*this->client_context, dataindexpX);
        Ciphertext clusterIndCipher(*this->client_pubkey);
        this->client_pubkey->Encrypt(clusterIndCipher, clusterInd);
        vector<Ciphertext> cluster;
        for (unsigned l = 0; l < this->k; l++) {
            cluster.push_back(clusterIndCipher);
        }

        this->A[identifier] = cluster;
        this->A_r[identifier] = cluster;
        this->cipherIDs[identifier] = identifier;
    }
    string message1 = this->receiveMessage(socketFD, 8);
    if (message1 != "C-DATA-E") {
        perror("ERROR IN PROTOCOL 3.1-STEP 7");
        return;
    }
    this->sendMessage(socketFD, "U-DATA-RECEIVED");
    print("PROTOCOL 3 COMPLETED");
    print("DATA RECEIVED - STARTING K-MEANS");
}

void UServerT2V1::initializeClustersandCentroids() {
    default_random_engine generator;
    uniform_int_distribution<int> distribution(0, this->k - 1);
    int seed;
    ZZ_pX dataindexpX;
    SetCoeff(dataindexpX, 0, 1);
    Plaintext clusterInd(*this->client_context, dataindexpX);
    Ciphertext clusterIndCipher(*this->client_pubkey);
    this->client_pubkey->Encrypt(clusterIndCipher, clusterInd);
    vector<unsigned> check;
    bool flag = true;
    for (auto &iter : this->A) {
        seed = distribution(generator);
        iter.second[seed] = clusterIndCipher;
        if (flag) {
            bool flag1 = true;
            for (unsigned int i : check) {
                if (i == seed) {
                    flag1 = false;
                }
            }
            if (flag1) {
                this->centroids[iter.first] = cipherpoints[iter.first];
                this->centroids_clusters[iter.first] = seed;
                auto cinf= static_cast<unsigned int>(seed);
                check.push_back(cinf);
            }
            if (check.size() == this->k) {
                flag = false;
            }

        }

    }
    for (auto &iter:this->centroids_clusters) {
        this->rev_centroids_clusters[iter.second] = this->cipherIDs[iter.first];
    }

}


void UServerT2V1::swapA() {
    this->A = this->A_r;
}

void UServerT2V1::connectToTServer() {
    struct sockaddr_in t_server_address;
    if (this->t_serverSocket == -1) {
        this->t_serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (this->t_serverSocket < 0) {
            perror("ERROR ON TSERVER SOCKET CREATION");
            exit(1);
        } else {
            string message =
                    "Socket for TServer created successfully. File descriptor: " + to_string(this->t_serverSocket);
            print(message);
        }

    }
    t_server_address.sin_addr.s_addr = inet_addr(this->t_serverIP.c_str());
    t_server_address.sin_family = AF_INET;
    t_server_address.sin_port = htons(static_cast<uint16_t>(this->t_serverPort));

    if (connect(this->t_serverSocket, (struct sockaddr *) &t_server_address, sizeof(t_server_address)) < 0) {
        perror("ERROR. CONNECTION FAILED TO TSERVER");

    } else {
        print("UServerT2V1 CONNECTED TO TSERVER");
    }

}

ifstream UServerT2V1::distanceToStream(const Ciphertext &distance) {
    ofstream ofstream1("distance.dat");
    Export(ofstream1, distance);
    return ifstream("distance.dat");
}

ifstream UServerT2V1::resultToStream(const Ciphertext &distance) {
    ofstream ofstream1("result.dat");
    Export(ofstream1, distance);
    return ifstream("result.dat");
}

void UServerT2V1::initializeKMToTServer() {
    this->connectToTServer();
    this->sendMessage(this->t_serverSocket, "U-KM");
    string message = this->receiveMessage(this->t_serverSocket, 7);
    if (message != "T-READY") {
        perror("ERROR IN PROTOCOL 4-STEP 1");
        return;
    }
    uint32_t k_factor = this->k;
    if (0 > send(this->t_serverSocket, &k_factor, sizeof(uint32_t), 0)) {
        perror("SEND K FAILED.");
        return;
    }
    string message1 = this->receiveMessage(this->t_serverSocket, 12);
    if (message1 != "T-K-RECEIVED") {
        perror("ERROR IN PROTOCOL 4-STEP 2");
        return;
    }
    uint32_t data_dimension = this->dim;
    if (0 > send(this->t_serverSocket, &data_dimension, sizeof(uint32_t), 0)) {
        perror("SEND DIMENSION FAILED.");
        return;
    }
    string message2 = this->receiveMessage(this->t_serverSocket, 14);
    if (message2 != "T-DIM-RECEIVED") {
        perror("ERROR IN PROTOCOL 4-STEP 3");
        return;
    }
    close(this->t_serverSocket);
    this->t_serverSocket = -1;

}

ifstream UServerT2V1::centroidToStream(const Ciphertext &centroid) {
    ofstream ofstream1("centroid.dat");
    Export(ofstream1, centroid);
    return ifstream("centroid.dat");
}

ifstream UServerT2V1::clusterSizeToStream(const Ciphertext &clustersize) {
    ofstream ofstream1("clustersize.dat");
    Export(ofstream1, clustersize);
    return ifstream("clustersize.dat");
}

void UServerT2V1::endKMToTserver() {
    this->connectToTServer();
    this->sendMessage(this->t_serverSocket, "UEKM");
    string message = this->receiveMessage(this->t_serverSocket, 5);
    if (message != "T-END") {
        perror("ERROR IN PROTOCOL 7-STEP 1");
        return;
    }
}

void UServerT2V1::resultsToKClient() {
    this->sendMessage(this->clientSocket, "U-RE");
    string message = this->receiveMessage(this->clientSocket, 7);
    if (message != "C-READY") {
        perror("ERROR IN PROTOCOL 8-STEP 1");
        return;
    }
    uint32_t k_factor= this->k;
    htonl(k_factor);
    if (0 > send(this->clientSocket, &k_factor, sizeof(uint32_t), 0)) {
        perror("SEND KMEANS K FAILED.");
        return;
    }

    for (auto &iter:this->A) {
        this->sendMessage(this->clientSocket, "U-P");
        string message1 = this->receiveMessage(this->clientSocket, 5);
        if (message1 != "C-P-R") {
            perror("ERROR IN PROTOCOL 8-STEP 2");
            return;
        }
        auto identity = (uint32_t) iter.first;
        htonl(identity);
        if (0 > send(this->clientSocket, &identity, sizeof(uint32_t), 0)) {
            perror("SEND IDENTITY FAILED.");
            return;
        }
        string message2 = this->receiveMessage(this->clientSocket, 5);
        if (message2 != "P-I-R") {
            perror("ERROR IN PROTOCOL 8-STEP 3");
            return;
        }

        for(unsigned i =0; i<this->k;i++){
            this->sendStream(this->resultToStream(iter.second[i]), this->clientSocket);
            string message3 = this->receiveMessage(this->clientSocket, 6);
            if (message3 != "P-CI-R") {
                perror("ERROR IN PROTOCOL 8-STEP 4");
                return;
            }
        }
        this->sendMessage(this->clientSocket,"U-R-P-E");
    }
    this->sendMessage(this->clientSocket, "U-RESULT-E");
    string message4 = this->receiveMessage(this->clientSocket, 5);
    if (message4 != "C-END") {
        perror("ERROR IN PROTOCOL 8-STEP 5");
        return;
    }

}