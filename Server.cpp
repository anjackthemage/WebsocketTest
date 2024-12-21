
#include "Server.h"
#include "Client.h"

#include "ws2tcpip.h"
#include "stdio.h"
#include "iostream"
#include "bcrypt.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

Server::Server()
{
}

Server::~Server()
{
}

int Server::Start()
{
	// Exit code
	int exit_code = 0;

	// Port used
	PCSTR port = "7022";
	// Initialize Winsock
	WSADATA wsaData;

	// Structure used to store the server address
	struct addrinfo* result = NULL, * ptr = NULL, hints;
	// Holds the result of the connection attempt
	int iResult;

	// Pointer to client.
	Client* client = nullptr;

	// Pointer to the Sec-WebSocket-Key header
	sec_websock_key = NULL;

	// The socket used to listen for incoming connections
	ListenSocket = INVALID_SOCKET;

	// This socket will be assigned to the new connection
	ClientSocket = INVALID_SOCKET;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		goto quit;
	}

	// Reserve memory for the connection struct
	ZeroMemory(&hints, sizeof(hints));
	// Set the address family to Internet
	hints.ai_family = AF_INET;
	// Set the socket type to stream
	hints.ai_socktype = SOCK_STREAM;
	// Set the protocol to TCP
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, port, &hints, &result);

	// Check if the address resolution was successful
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		goto quit;
	}

	// Initialize the listen socket.
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	// Check if the socket was created successfully
	if (ListenSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		goto quit;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("Failed to bind socket: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		goto quit;
	}

	// Free the address info
	freeaddrinfo(result);

	// Start listening on the socket
	iResult = listen(ListenSocket, SOMAXCONN);

	// Check if the listen was successful
	if (iResult == SOCKET_ERROR) {
		printf("Listen failed with error: %ld\n", WSAGetLastError());
		goto quit;
	}

	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);

	// Check if the connection was successful
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed: %d\n", WSAGetLastError());
		goto quit;
	}

	// Instantiate the client
	client = new Client();
	// Start the client
	exit_code = client->Start(ClientSocket);

quit:
	// Clean up the client
	if (client != nullptr) {
		delete client;
	}

	// No longer need the server socket
	closesocket(ListenSocket);
	// No longer need the client socket
	closesocket(ClientSocket);
	// Cleanup
	WSACleanup();


	return exit_code;
}
