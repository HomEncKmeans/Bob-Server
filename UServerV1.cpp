//
// Created by george on 16/11/2017.
//

#include "UServerV1.h"


UServerV1::UServerV1(string u_serverIP, int u_serverPort, bool verbose) {

    this->active = true;
    this->verbose=verbose;
    this->u_serverIP = move(u_serverIP);
    this->u_serverPort = u_serverPort;
    print("UNTRUSTED SERVER V1");
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
    print("CLIENT - UServerV1 SWITCH MATRIX ");
    print(keySwitchSI);
    while (this->active) {
        this->socketAccept();
    }
}

void UServerV1::socketCreate() {
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

void UServerV1::socketBind() {
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

void UServerV1::socketListen() {
    listen(this->u_serverSocket, 5);
    print("Server is listening...");

}

void UServerV1::socketAccept() {
    int socketFD;
    socketFD = accept(this->u_serverSocket, NULL, NULL);
    if (socketFD < 0) {
        perror("SOCKET ACCEPT ERROR");
    } else {
        print("CLIENT_CONNECTED");
        this->handleRequest(socketFD);
    }

}

void UServerV1::handleRequest(int socketFD) {
    string message = this->receiveMessage(socketFD, 4);
    if (message == "C-PK") {
        this->receiveEncryptionParamFromClient(socketFD);
    } else if (message == "C-DA") {
        this->receiveEncryptedData(socketFD);
    } else if (message == "T-DP") {
        this->sendDistances(socketFD);
    } else if (message == "T-NC") {
        this->receiveCentroids(socketFD);
    } else if (message == "TEKM") {
        this->sendMessage(socketFD, "U-END");
        this->active = false;
        print("UServerV1 STOP AND EXIT");
    } else {
        perror("ERROR IN PROTOCOL INITIALIZATION");
        return;
    }

}

bool UServerV1::sendStream(ifstream data, int socket) {
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

bool UServerV1::sendMessage(int socketFD, string message) {
    if (send(socketFD, message.c_str(), strlen(message.c_str()), 0) < 0) {
        perror("SEND FAILED.");
        return false;
    } else {
        this->log(socketFD, "<--- " + message);
        return true;
    }
}

string UServerV1::receiveMessage(int socketFD, int buffersize) {
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

ifstream UServerV1::receiveStream(int socketFD, string filename) {
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
        ssize_t data_fd=recv(socketFD, memblock+received_data, 1000, 0);
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

void UServerV1::log(int socket, string message) {
    if(this->verbose) {
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
}

void UServerV1::receiveEncryptionParamFromClient(int socketFD) {
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

void UServerV1::receiveEncryptedData(int socketFD) {
    this->sendMessage(socketFD,"U-DATA-READY");
    uint32_t dimension;
    auto *data1 = (char *) &dimension;
    if (recv(socketFD, data1, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 2");
    }
    ntohl(dimension);
    this->log(socketFD, "--> Data dimension: " + to_string(dimension));
    this->dim=dimension;
    this->sendMessage(socketFD,"U-D-RECEIVED");
    uint32_t numberofpoints;
    auto *data2 = (char *) &numberofpoints;
    if (recv(socketFD, data2, sizeof(uint32_t), 0) < 0) {
        perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 3");
    }
    ntohl(numberofpoints);
    this->log(socketFD, "--> Number of Points: " + to_string(numberofpoints));
    this->number_of_points=numberofpoints;
    this->sendMessage(socketFD,"U-N-RECEIVED");
    string message = this->receiveMessage(socketFD,8);
    if (message != "C-DATA-P") {
        perror("ERROR IN PROTOCOL 3.1-STEP 4");
        return;
    }
    this->sendMessage(socketFD,"U-DATA-P-READY");
    for(unsigned i=0; i<this->number_of_points;i++){
        uint32_t identifier;
        auto *data = (char *) &identifier;
        if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
            perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 5");
        }
        ntohl(identifier);
        this->sendMessage(socketFD,"U-P-I-RECEIVED");
        vector<Ciphertext> encrypted_point;
        for(unsigned j=0; j<this->dim;j++){
            uint32_t index;
            auto *data3 = (char *) &index;
            if (recv(socketFD, data3, sizeof(uint32_t), 0) < 0) {
                perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 3.1-STEP 6");
            }
            ntohl(index);
            this->sendMessage(socketFD,"U-INDEX-RECEIVED");
            string filename = "coef_" + to_string(j) + ".dat";
            ifstream cipher = this->receiveStream(socketFD, filename);
            Ciphertext ciphertext(*this->client_pubkey);
            ifstream in(filename);
            Import(in, ciphertext);
            encrypted_point.push_back(ciphertext);
            this->sendMessage(socketFD,"U-COEF-RECEIVED");
        }
        this->cipherpoints[identifier]=encrypted_point;
    }

    string message1 = this->receiveMessage(socketFD,8);
    if (message1 != "C-DATA-E") {
        perror("ERROR IN PROTOCOL 3.1-STEP 7");
        return;
    }
    this->sendMessage(socketFD,"U-DATA-RECEIVED");
    print("PROTOCOL 3 COMPLETED");

}

void UServerV1::receiveCentroids(int socketFD) {
    this->sendMessage(socketFD,"U-NC-READY");
    bool flag= true;
    while(flag){
        uint32_t cluster_index;
        auto *data = (char *) &cluster_index;
        if (recv(socketFD, data, sizeof(uint32_t), 0) < 0) {
            perror("RECEIVE CLUSTER INDEX ERROR. ERROR IN PROTOCOL 6-STEP 2");
        }
        ntohl(cluster_index);
        this->sendMessage(socketFD,"U-RECEIVED-CI");
        vector<Ciphertext> centroid;
        for(unsigned i=0;i<this->dim;i++){
            uint32_t coef_index;
            auto *data1 = (char *) &coef_index;
            if (recv(socketFD, data1, sizeof(uint32_t), 0) < 0) {
                perror("RECEIVE COEFFICIENT INDEX ERROR. ERROR IN PROTOCOL 6-STEP 3");
            }
            ntohl(coef_index);
            this->sendMessage(socketFD,"U-INDEX-RECEIVED");
            string filename = "coef_" + to_string(i) + ".dat";
            ifstream cipher = this->receiveStream(socketFD, filename);
            Ciphertext ciphertext(*this->client_pubkey);
            ifstream in(filename);
            Import(in, ciphertext);
            if(i==coef_index) {
                centroid.push_back(ciphertext);
            }
            this->sendMessage(socketFD,"U-COEF-RECEIVED");
        }
        string message = this->receiveMessage(socketFD,8);
        if (message == "T-NC-END") {
            this->centroids[cluster_index]=centroid;
            this->sendMessage(socketFD,"U-NC-RECEIVED");
        } else if(message == "T-NC-UPD"){
            this->centroids[cluster_index]=centroid;
            this->sendMessage(socketFD,"U-READY");
            flag= false;
        } else{
            perror("ERROR IN PROTOCOL 6-STEP 4");
            return;
        }
    }

}

void UServerV1::sendDistances(int socketFD) {
    this->sendMessage(socketFD,"U-READY");

    for(auto &iter:this->cipherpoints){
        uint32_t identifier = iter.first;
        htonl(identifier);
        if (0 > send(socketFD, &identifier, sizeof(uint32_t), 0)) {
            perror("ERROR IN PROTOCOL 5-STEP 2.");
            return;
        }
        string message = this->receiveMessage(socketFD, 5);
        if (message != "T-R-I") {
            perror("ERROR IN PROTOCOL 5-STEP 3");
            return;
        }
        for(auto &iter1:this->centroids){
            uint32_t index_of_cluster = iter1.first;
            htonl(index_of_cluster);
            if (0 > send(socketFD, &index_of_cluster, sizeof(uint32_t), 0)) {
                perror("ERROR IN PROTOCOL 5-STEP 4.");
                return;
            }
            string message1 = this->receiveMessage(socketFD, 6);
            if (message1 != "T-R-CI") {
                perror("ERROR IN PROTOCOL 5-STEP 4");
                return;
            }
            Ciphertext distance;
            distance = euclideanDistance(iter.second,iter1.second,*this->client_SM);
            this->sendStream(this->distanceToStream(distance), socketFD);
            string message2 = this->receiveMessage(socketFD, 5);
            if (message2 != "T-R-D") {
                perror("ERROR IN PROTOCOL 5-STEP 5");
                return;
            }
        }
        string message3 = this->receiveMessage(socketFD, 7);
        if (message3 != "T-R-D-P") {
            perror("ERROR IN PROTOCOL 5-STEP 6");
            return;
        }
    }
    this->sendMessage(socketFD,"U-F-D");
    string message4 = this->receiveMessage(socketFD, 7);
    if (message4 != "T-READY") {
        perror("ERROR IN PROTOCOL 5-STEP 7");
        return;
    }
}

ifstream UServerV1::distanceToStream(const Ciphertext &distance) {
    ofstream ofstream1("distance.dat");
    Export(ofstream1, distance);
    return ifstream("distance.dat");
}