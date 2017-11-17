//
// Created by george on 7/11/2017.
//

#include "Server.h"


struct ClientRequest {
    int socketFD;
    string request;
};

struct ServerAndSocket {
    Server *socketServer;
    int socketFD;
};


Server::Server(string serverIp, int serverPort, string addressT, int portT) {
    this->serverIp = serverIp;
    this->serverPort = serverPort;
    this->addressT=addressT;
    this->portT = portT;
    this->socketCreate();
    this->socketBind();
    this->socketListen();
    this->socketAccept();

};

void Server::socketCreate() {
    this->masterSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (this->masterSocket < 0) {
        perror("Socket Error");
        exit(1);
    } else {
        int opt = 1;
        setsockopt(this->masterSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        cout << "Socket created successfully with file descriptor " << this->masterSocket << "\n";
    };
};

void Server::socketBind() {
    struct sockaddr_in serverAddress;

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(this->serverPort);
    serverAddress.sin_addr.s_addr = inet_addr(this->serverIp.data());

    if (bind(this->masterSocket, (sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("Bind Error");
        exit(1);
    } else {
        cout << "Socket bound successfully to the " << this->serverIp << ":" << this->serverPort << " address\n";
    };
};

void Server::socketListen() {
    listen(this->masterSocket, 5);
    cout << "Socket is beeing listened now\n";
};


void Server::socketAccept() {
    int socketFD;
        socketFD = accept(this->masterSocket, NULL, NULL);
        if (socketFD < 0) {
            perror("Accept");
        } else {
            std::cout<<"CLIENT_CONNECTED"<<std::endl;
            this->handleRequest(socketFD);
            std::cout<<socketFD<<std::endl;
        }
}


void Server::handleRequest(int socketFD) {

    if(this->GMODE){
        string message= this-> readData(socketFD,4);
        print(message);
        if(message=="C-PK"){
            this->sendData(socketFD,"U-PK-READY");

            this->readStream(socketFD);
            //this->defineMode(false,true,false,false,false);
            this->protocol_step+=1;
        } else{
            cout<<"here"<<endl;
        }

    } else if(this->PMODE){

    } else if(this->DMODE){

    } else if(this->KMODE1){

    } else if(this->KMODE2){

    } else{
        perror("ERROR OPERATIONAL MODE");
    }

}

string Server::readData(int socketFD,int length) {
    char buffer[length];
    string reply;

    if( recv(socketFD , buffer , sizeof(buffer) , 0) < 0) {
        perror("ERROR RECEIVING DATA");
    }
    reply = buffer;
    return reply;
};





ifstream Server::readStream(int socketPointer) {

    char input[1024];
    int inputLength;
    int socketFD;
    socketFD = socketPointer;
    memset((void *) &input, '\0', sizeof(input));
    inputLength = recv(socketFD, (void *) &input, 1024,0);
    if (inputLength < 0) {
        perror("Read");
    }

}







void Server::sendData(int socketFD, string message) {
    int bytesWritten;
    bytesWritten = send(socketFD, message.c_str(),strlen(message.c_str()) ,0);
    if (bytesWritten < 0) {
        perror("Write");
    } else {
        this->log(socketFD, "<--- " + message);
    };
}

void Server::log(int socketFD, string message) {
    sockaddr address;
    socklen_t addressLength;
    sockaddr_in *addressInternet;
    string ip;
    int port;
    getpeername(socketFD, &address, &addressLength);
    addressInternet = (struct sockaddr_in *) &address;
    ip = inet_ntoa(addressInternet->sin_addr);
    port = addressInternet->sin_port;
    cout << ip << ":" << port << " " << message << "\n";
}



void Server::defineMode(bool GMODE, bool PMODE, bool DMODE, bool KMODE1, bool KMODE2) {
    this->KMODE1=KMODE1;
    this->KMODE2=KMODE2;
    this->GMODE=GMODE;
    this->DMODE=DMODE;
    this->PMODE=PMODE;

}