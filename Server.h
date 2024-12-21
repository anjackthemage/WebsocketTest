#pragma once

#include "winsock2.h"

class Server
{
public:
	
	Server();
	~Server();
	
	int Start();

	SOCKET ListenSocket = NULL;

	SOCKET ClientSocket = NULL;

	char* sec_websock_key = NULL;

	// Buffer used to send and receive data
	const char* sendbuf = "SUCCECSS";
	// Length of receive buffer
	static const int recvbuflen = 512;
	// Buffer used to receive data
	char recvbuf[recvbuflen];
};