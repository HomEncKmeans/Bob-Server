//
// Created by george on 16/11/2017.
//

#include "UServer.h"


UServer::UServer(string u_serverIP, int u_serverPort, string t_serverIP, int t_serverPort, int k) {
    this->k=k;
    this->u_serverIP = move(u_serverIP);
    this->u_serverPort = u_serverPort;
    this->t_serverIP = move(t_serverIP);
    this->t_serverPort = t_serverPort;
    print("UNTRUSTED SERVER");
    this->socketCreate();
    this->socketBind();
    this->socketListen();
    this->socketAccept();
    print("CLIENT ENCRYPTION PARAMETERS");
    ifstream contextfile("context.dat");
    FHEcontext fhEcontext(contextfile);
    this->client_context=&fhEcontext;
    activeContext=&fhEcontext;
    ifstream pkC("pkC.dat");
    FHESIPubKey fhesiPubKey(fhEcontext);
    fhesiPubKey.Import(pkC);
    this->client_pubkey=&fhesiPubKey;
    ifstream smC("smC.dat");
    KeySwitchSI keySwitchSI(fhEcontext);
    keySwitchSI.Import(smC);
    this->client_SM=&keySwitchSI;
    print("CONTEXT");
    print(fhEcontext);
    print("CLIENT PUBLIC KEY");
    print(fhesiPubKey);
    print("CLIENT - USERVER SWITCH MATRIX ");
    print(keySwitchSI);
    this->socketAccept();
    print("--------------------POINTS--------------------");
    for (auto &iter : this->A) {
        cout << "Point ID: " << iter.first << " Cluster: " << iter.second << endl;
    }
    print("--------------------CIPHERTEXTS--------------------");
    for (auto &iter : this->cipherMAP) {
        cout << "Point ID: " << iter.first << " Ciphertext: " << iter.second << endl;
        Ciphertext ciphertext(fhesiPubKey);
        ifstream in(iter.second);
        Import(in,ciphertext);
        print(ciphertext);
        this->cipherpoints[iter.first]=ciphertext;
    }
    print("END of DATA ");
    this->socketAccept();

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

ifstream UServer::receiveStream(int socketFD,string filename) {
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
    this->receiveStream(socketFD,"pkC.dat");
    this->sendMessage(socketFD, "U-PK-RECEIVED");
    string message = this->receiveMessage(socketFD, 4);
    if (message != "C-SM") {
        perror("ERROR IN PROTOCOL 1-STEP 2");
        return;
    }
    this->sendMessage(socketFD, "U-SM-READY");
    this->receiveStream(socketFD,"smC.dat");
    this->sendMessage(socketFD, "U-SM-RECEIVED");
    string message1 = this->receiveMessage(socketFD,9);
    if(message1!="C-CONTEXT"){
        perror("ERROR IN PROTOCOL 2-STEP 4");
        return;
    }
    this->sendMessage(socketFD,"U-C-READY");
    this->receiveStream(socketFD,"context.dat");
    this->sendMessage(socketFD,"U-C-RECEIVED");

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
    int i=0;
    while (flag) {
        this->sendMessage(socketFD, "U-DATA-P-READY");
        string filename= "point_"+to_string(i)+".dat";
        ifstream cipher=this->receiveStream(socketFD,filename);
        std::string buffer((std::istreambuf_iterator<char>(cipher)),std::istreambuf_iterator<char>());
        hash<string> str_hash;
        size_t hash_value=str_hash(buffer);
        bitset<6> cluster;
        this->A[hash_value]=cluster;
        this->cipherMAP[hash_value]=filename;
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
    this->sendMessage(socketFD,"U-DATA-RECEIVED");
    print("DATA RECEIVED - STARTING K-MEANS");
}

