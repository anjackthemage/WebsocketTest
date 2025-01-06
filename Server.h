#pragma once

#include "winsock2.h"
#include "vector"

class Client;

class Server
{
public:
	
	Server();
	~Server();
	
	int Start();

	int Stop();

	void ListenForIncomingConnections();

	void HandleIncomingConnections();

	void CheckForIncomingMessages();

	SOCKET ListenSocket = NULL;

	SOCKET client_socket = NULL;

	char* sec_websock_key = NULL;

	// Buffer used to send and receive data
	const char* sendbuf = "SUCCECSS";
	// Length of receive buffer
	static const int recvbuflen = 512;
	// Buffer used to receive data
	char recvbuf[recvbuflen];

	// True when server is shutting down
	bool b_shutdown = false;

	// Vector containing connected clients.
	std::vector<Client*> clients;
};