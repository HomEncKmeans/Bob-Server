//
// Created by george on 16/11/2017.
//

#include "UServer.h"



UServer::UServer(string u_serverIP, int u_serverPort, string t_serverIP, int t_serverPort) {
    this->u_serverIP= move(u_serverIP);
    this->u_serverPort=u_serverPort;
    this->t_serverIP= move(t_serverIP);
    this->t_serverPort=t_serverPort;
    print("UNTRUSTED SERVER");
    this->socketCreate();
    this->socketBind();
    this->socketListen();
    this->socketAccept();
    this->handleRequest(this->u_serverSocket);

}


void UServer::socketCreate() {
    this->u_serverSocket=socket(AF_INET,SOCK_STREAM,0);
    if(this->u_serverSocket<0){
        perror("ERROR IN SOCKET CREATION");
        exit(1);
    }else{
        int opt=1;
        setsockopt(this->u_serverSocket,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
        string message = "Socket created successfully. File descriptor: "+to_string(this->u_serverSocket);
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
        string message= "Socket bound successfully to :["+u_serverIP+":"+to_string(this->u_serverPort)+ "]";
        print(message);
    }

}

void UServer::socketListen() {
    listen(this->u_serverSocket,5);
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

void UServer::handleRequest(int) {

}

bool UServer::sendStream(ifstream data, int socket){
    streampos begin,end;
    begin =data.tellg();
    data.seekg(0,ios::end);
    end=data.tellg();
    streampos size = end-begin;
    streampos *sizeref = &size;
    print(size);
    auto * memblock = new char [size];
    data.seekg (0, std::ios::beg);
    data.read (memblock, size);
    data.close();
    if(0 > send(socket, sizeref, sizeof(size), 0)){
        perror("SEND FAILED.");
        return false;
    }else {
        if (send(socket, memblock, static_cast<size_t>(size), 0) < 0) {
            perror("SEND FAILED.");
            return false;
        } else {
            return true;
        }
    }
}

bool UServer::sendMessage(int socketFD, string message) {
    if( send(socketFD , message.c_str() , strlen( message.c_str() ) , 0) < 0){
        perror("SEND FAILED.");
        return false;
    }else{
        this->log(socketFD,"<--- "+message);
        return true;
    }
}

string UServer::receiveMessage(int socketFD, int buffersize) {
    char buffer[buffersize];
    string message;
    if(recv(socketFD, buffer, static_cast<size_t>(buffersize), 0) < 0){
        perror("RECEIVE FAILED");
    }
    message=buffer;
    this->log(socketFD,"---> "+message);
    return message;
}

ifstream UServer::receiveStream(int) {
    return std::ifstream();
}

void UServer::log(int socket, string message){
    sockaddr address;
    socklen_t addressLength;
    sockaddr_in *addressInternet;
    string ip;
    int port;
    getpeername(socket, &address, &addressLength);
    addressInternet = (struct sockaddr_in *) &address;
    ip = inet_ntoa(addressInternet->sin_addr);
    port = addressInternet->sin_port;
    string msg = "["+ip+":"+to_string(port)+"] "+message;
    print(msg);
}