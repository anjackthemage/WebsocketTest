#pragma once

#include "winsock2.h"

class Client
{
public:

	Client();
	~Client();

	int Start(SOCKET& InConnectSocket);

	int Stop();

	bool IsMessagePending();

	void HandleIncomingMessage();

	SOCKET ConnectSocket = INVALID_SOCKET;

	char* sec_websock_key = NULL;

	// Buffer used to send and receive data
	const char* sendbuf = "SUCCESS";
	// Length of receive buffer
	static const int recvbuflen = 1024;
	// Buffer used to receive data
	char recvbuf[recvbuflen];

	// True when client is shutting down
	bool b_shutdown = false;
};