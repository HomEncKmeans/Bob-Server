//
// Created by george on 16/11/2017.
//

#include "UServer.h"


UServer::UServer(string u_serverIP, int u_serverPort, string t_serverIP, int t_serverPort, unsigned k, int max_round,
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
    print("CLIENT - USERVER SWITCH MATRIX ");
    print(keySwitchSI);
    this->socketAccept();
    print("K-MEANS-INITIALIZATION");
    this->initializeKMToTServer();
    this->initializeClusters();
    for (auto &iter : this->cipherMAP) {
        Ciphertext ciphertext(*this->client_pubkey);
        ifstream in(iter.second);
        Import(in, ciphertext);
        this->cipherpoints[iter.first] = ciphertext;
    }
    this->initializeCentroids();
    print("END OF K-MEANS INITIALIZATION");
    print("----------------------------------");
    print("STARTING K-MEANS ROUNDS");
    int r = 0;
    long s = this->calculateVariance();
    while (r < this->max_round && s >= this->variance_bound) {
        print("ROUND: "+to_string(r));
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
                    perror("SEND K FAILED.");
                    return;
                }
                string message1 = this->receiveMessage(this->t_serverSocket, 13);
                if (message1 != "T-RECEIVED-CI") {
                    perror("ERROR IN PROTOCOL 5-STEP 2");
                    return;
                }
                Ciphertext distance(*this->client_pubkey);
                distance = FHE_HM(this->cipherpoints[iter.first], this->centroids[this->rev_centroids_clusters[i]]);
                this->sendStream(this->distanceToStream(distance), this->t_serverSocket);
                string message2 = this->receiveMessage(this->t_serverSocket, 12);
                if (message2 != "T-D-RECEIVED") {
                    perror("ERROR IN PROTOCOL 5-STEP 3");
                    return;
                }
            }
            this->sendMessage(this->t_serverSocket, "U-R-I");
            uint32_t index;
            auto *data = (char *) &index;
            if (recv(this->t_serverSocket, data, sizeof(uint32_t), 0) < 0) {
                perror("RECEIVE INDEX ERROR. ERROR IN PROTOCOL 5-STEP 4");
            }
            ntohl(index);
            this->log(this->t_serverSocket, "--> INDEX: " + to_string(index));
            iter.second[index] = 1;
            this->sendMessage(this->t_serverSocket, "U-RECEIVED-I");
            close(this->t_serverSocket);
            this->t_serverSocket = -1;
        }
        s = this->calculateVariance();
        r++;
        print(r);
        this->swapA();
        if (r < this->max_round && s >= this->variance_bound) {
            this->connectToTServer();
            print("CREATE NEW CENTROIDS");
            this->sendMessage(this->t_serverSocket, "U-NC");
            string message3 = this->receiveMessage(this->t_serverSocket, 10);
            if (message3 != "T-NC-READY") {
                perror("ERROR IN PROTOCOL 6-STEP 1");
                return;
            }
            this->centroids_clusters.clear();
            this->centroids.clear();
            for (unsigned i = 0; i < this->k; i++) {
                uint32_t index = i;
                if (0 > send(this->t_serverSocket, &index, sizeof(uint32_t), 0)) {
                    perror("SEND INDEX FAILED.");
                    return;
                }
                string message4 = this->receiveMessage(this->t_serverSocket, 13);
                if (message4 != "T-RECEIVED-CI") {
                    perror("ERROR IN PROTOCOL 6-STEP 2");
                    return;
                }
                vector<size_t> cluster_members;
                for (auto &iter:this->A) {
                    if (iter.second[i] == 1) {
                        cluster_members.push_back(this->cipherIDs[iter.first]);
                    }
                }
                Ciphertext total;
                total = this->cipherpoints[cluster_members[0]];
                for (unsigned j = 1; j < cluster_members.size(); j++) {
                    total += this->cipherpoints[cluster_members[j]];
                }
                this->sendStream(this->centroidsToStream(total), this->t_serverSocket);
                string message5 = this->receiveMessage(this->t_serverSocket, 12);
                if (message5 != "T-RECEIVED-C") {
                    perror("ERROR IN PROTOCOL 6-STEP 3");
                    return;
                }
                Ciphertext centroid(*this->client_pubkey);
                ifstream cipherCentroid = this->receiveStream(this->t_serverSocket, to_string(index) + "-centroid.dat");
                std::string buffer((std::istreambuf_iterator<char>(cipherCentroid)), std::istreambuf_iterator<char>());
                hash<string> str_hash;
                size_t hash_value = str_hash(buffer);
                ifstream in(to_string(index) + "-centroid.dat");
                Import(in, centroid);
                this->rev_centroids_clusters[i] = hash_value;
                this->centroids_clusters[hash_value] = i;
                this->centroids[hash_value] = centroid;
                this->sendMessage(this->t_serverSocket, "U-NC-RECEIVED");
            }
            this->sendMessage(this->t_serverSocket, "U-C-UPDATED");
            string message6 = this->receiveMessage(this->t_serverSocket, 7);
            if (message6 != "T-READY") {
                perror("ERROR IN PROTOCOL 6-STEP 4");
                return;
            }
            close(this->t_serverSocket);
            this->t_serverSocket = -1;
        }

    }
    this->endKMToTserver();
    this->resultsToKClient();
    print("END-OF-KMEANS");
    //this->socketAccept();

}

void UServer::socketCreate() {
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

void UServer::socketBind() {
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

void UServer::socketListen() {
    listen(this->u_serverSocket, 5);
    print("Server is listening...");

}

void UServer::socketAccept() {
    int socketFD;
    socketFD = accept(this->u_serverSocket, NULL, NULL);
    if (socketFD < 0) {
        perror("SOCKET ACCEPT ERROR");
    } else {
        print("CLIENT_CONNECTED");
        this->handleRequest(socketFD);
    }

}

void UServer::handleRequest(int socketFD) {
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

bool UServer::sendStream(ifstream data, int socket) {
    streampos begin, end;
    begin = data.tellg();
    data.seekg(0, ios::end);
    end = data.tellg();
    streampos size = end - begin;
    uint32_t sizek = size;
    auto *memblock = new char[sizek];
    data.seekg(0, std::ios::beg);
    data.read(memblock, sizek);
    data.close();
    htonl(sizek);
    if (0 > send(socket, &sizek, sizeof(uint32_t), 0)) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socket, "<--- " + to_string(sizek));
        if (this->receiveMessage(socket, 7) == "SIZE-OK") {
            ssize_t r = (send(socket, memblock, static_cast<size_t>(size), 0));
            print(r); //for debugging
            if (r < 0) {
                perror("SEND FAILED.");
                return false;
            } else {
                return true;
            }
        } else {
            perror("SEND SIZE ERROR");
            return false;
        }
    }
}

bool UServer::sendMessage(int socketFD, string message) {
    if (send(socketFD, message.c_str(), strlen(message.c_str()), 0) < 0) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socketFD, "<--- " + message);
        return true;
    }
}

string UServer::receiveMessage(int socketFD, int buffersize) {
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

ifstream UServer::receiveStream(int socketFD, string filename) {
    uint32_t size;
    auto *data = (char *) &size;
    if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE SIZE ERROR");
    }
    ntohl(size);
    this->log(socketFD, "--> SIZE: " + to_string(size));
    this->sendMessage(socketFD, "SIZE-OK");
    char buffer[size];
    ssize_t r = recv(socketFD, buffer, size, 0);
    print(r);
    if (r < 0) {
        perror("RECEIVE STREAM ERROR");
    }
    ofstream temp(filename, ios::out | ios::binary);
    temp.write(buffer, size);
    temp.close();

    return ifstream(filename);
}

void UServer::log(int socket, string message) {
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

void UServer::receiveEncryptionParamFromClient(int socketFD) {
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

void UServer::receiveEncryptedData(int socketFD) {
    bool flag = true;
    this->sendMessage(socketFD, "U-DATA-READY");
    string message = this->receiveMessage(socketFD, 8);
    if (message != "C-DATA-P") {
        perror("ERROR IN PROTOCOL 3-STEP 2");
        return;
    }
    int i = 0;
    while (flag) {
        this->sendMessage(socketFD, "U-DATA-P-READY");
        string filename = "point_" + to_string(i) + ".dat";
        ifstream cipher = this->receiveStream(socketFD, filename);
        std::string buffer((std::istreambuf_iterator<char>(cipher)), std::istreambuf_iterator<char>());
        hash<string> str_hash;
        size_t hash_value = str_hash(buffer);
        bitset<6> cluster;
        this->A[hash_value] = cluster;
        this->A_r[hash_value] = cluster;
        this->cipherMAP[hash_value] = filename;
        this->cipherIDs[hash_value] = hash_value;
        this->sendMessage(socketFD, "U-DATA-P-RECEIVED");
        string message1 = this->receiveMessage(socketFD, 8);
        if (message1 == "C-DATA-P") {
            flag = true;
        } else if (message1 == "C-DATA-E") {
            flag = false;
        } else {
            perror("ERROR IN PROTOCOL 3-STEP 3");
            return;
        }
        i++;
    }
    this->sendMessage(socketFD, "U-DATA-RECEIVED");
    print("DATA RECEIVED - STARTING K-MEANS");
}

void UServer::initializeClusters() {
    default_random_engine generator;
    uniform_int_distribution<int> distribution(0, this->k - 1);
    int seed;
    for (auto &iter : this->A) {
        seed = distribution(generator);
        iter.second[seed] = 1;
    }
}

void UServer::initializeCentroids() {
    for (int i = 0; i < this->k; i++) {
        for (auto &iter : this->A) {
            if (iter.second[i] == 1) {
                this->centroids[iter.first] = cipherpoints[iter.first];
                this->centroids_clusters[iter.first] = i;
                break;
            }
        }
    }
    for (auto &iter:this->centroids_clusters) {
        this->rev_centroids_clusters[iter.second] = this->cipherIDs[iter.first];
    }
}

long UServer::calculateVariance() {
    int variance = 0;
    bitset<6> zeroset;
    for (auto &iter:this->A) {
        if (zeroset != (iter.second ^ this->A_r[iter.first])) {
            variance++;
        }
    }
    return variance;
}

void UServer::swapA() {
    this->A = this->A_r;
    bitset<6> zeroset;
    for (auto &iter:this->A_r) {
        iter.second = zeroset;
    }
}

void UServer::connectToTServer() {
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
        print("USERVER CONNECTED TO TSERVER");
    }

}

ifstream UServer::distanceToStream(const Ciphertext &distance) {
    ofstream ofstream1("distance.dat");
    Export(ofstream1, distance);
    return ifstream("distance.dat");
}

void UServer::initializeKMToTServer() {
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
    close(this->t_serverSocket);
    this->t_serverSocket = -1;

}

ifstream UServer::centroidsToStream(const Ciphertext &centroid) {
    ofstream ofstream1("centroid.dat");
    Export(ofstream1, centroid);
    return ifstream("centroid.dat");
}

void UServer::endKMToTserver() {
    this->connectToTServer();
    this->sendMessage(this->t_serverSocket, "UEKM");
    string message = this->receiveMessage(this->t_serverSocket, 5);
    if (message != "T-END") {
        perror("ERROR IN PROTOCOL 7-STEP 1");
        return;
    }
}

void UServer::resultsToKClient() {
    this->sendMessage(this->clientSocket, "U-RESULT");
    string message = this->receiveMessage(this->clientSocket, 7);
    if (message != "K-READY") {
        perror("ERROR IN PROTOCOL 8-STEP 1");
        return;
    }
    for (auto &iter:this->A) {
        this->sendMessage(this->clientSocket, "U-P");
        string message1 = this->receiveMessage(this->clientSocket, 5);
        if (message1 != "U-P-R") {
            perror("ERROR IN PROTOCOL 8-STEP 2");
            return;
        }
        auto identity =(uint32_t) iter.first;
        if (0 > send(this->clientSocket, &identity, sizeof(uint32_t), 0)) {
            perror("SEND IDENTITY FAILED.");
            return;
        }
        string message2 = this->receiveMessage(this->clientSocket, 5);
        if (message2 != "P-I-R") {
            perror("ERROR IN PROTOCOL 8-STEP 3");
            return;
        }
        uint32_t index;
        for (unsigned i = 0; i < this->k; i++) {
            if (iter.second[i] == 1) {
                index = i;
            }
        }
        if (0 > send(this->clientSocket, &index, sizeof(uint32_t), 0)) {
            perror("SEND CLUSTER INDEX FAILED.");
            return;
        }
        string message3 = this->receiveMessage(this->clientSocket, 6);
        if (message3 != "P-CI-R") {
            perror("ERROR IN PROTOCOL 8-STEP 3");
            return;
        }
    }
    this->sendMessage(this->clientSocket, "U-RESULT-E");
    string message4 = this->receiveMessage(this->clientSocket, 5);
    if (message4 != "K-END") {
        perror("ERROR IN PROTOCOL 8-STEP 3");
        return;
    }

}