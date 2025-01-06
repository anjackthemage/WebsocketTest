
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
	// Clean up all clients
	for (Client* client : clients) {
		delete client;
	}

	// No longer need the server socket
	closesocket(ListenSocket);
	// No longer need the client socket
	closesocket(client_socket);
	// Cleanup
	WSACleanup();

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

	// Pointer to the Sec-WebSocket-Key header
	sec_websock_key = NULL;

	// The socket used to listen for incoming connections
	ListenSocket = INVALID_SOCKET;

	// This socket will be assigned to the new connection
	client_socket = INVALID_SOCKET;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		exit_code = 1;
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
		exit_code = 2;
		goto quit;
	}

	// Initialize the listen socket.
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	// Check if the socket was created successfully
	if (ListenSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		exit_code = 3;
		goto quit;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("Failed to bind socket: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		exit_code = 4;
		goto quit;
	}

	// Free the address info
	freeaddrinfo(result);

	// Start listening on the socket
	iResult = listen(ListenSocket, SOMAXCONN);

	// Check if the listen was successful
	if (iResult == SOCKET_ERROR) {
		printf("Listen failed with error: %ld\n", WSAGetLastError());
		exit_code = 5;
		goto quit;
	}

	//while (true)
	//{
	//	// Accept a client socket
	//	ClientSocket = accept(ListenSocket, NULL, NULL);

	//	// Check if the connection was successful
	//	if (ClientSocket == INVALID_SOCKET) {
	//		printf("accept failed: %d\n", WSAGetLastError());
	//		goto quit;
	//	}

	//	// Instantiate the client
	//	client = new Client();

	//	// Add the client to the list of connected clients
	//	clients.push_back(*client);

	//	// Start the client
	//	int ClientResult = client->Start(ClientSocket);
	//}

quit:

	return exit_code;
}

int Server::Stop()
{
	// Set the shutdown flag
	b_shutdown = true;
	return 0;
}

void Server::ListenForIncomingConnections()
{
	while (!b_shutdown)
	{
		// Check for incoming connections
		HandleIncomingConnections();

		// #TODO: Implement client heartbeat check

		// Check for incoming messages
		CheckForIncomingMessages();
	}
}

void Server::HandleIncomingConnections()
{
	//while (true)
	//{
	//	// Accept a client socket
	//	client_socket = accept(ListenSocket, NULL, NULL);

	//	// Check if the connection was successful
	//	if (client_socket == INVALID_SOCKET) {
	//		printf("accept failed: %d\n", WSAGetLastError());
	//		goto quit;
	//	}

	//	// Instantiate the client
	//	client = new Client();

	//	// Add the client to the list of connected clients
	//	clients.push_back(*client);

	//	// Start the client
	//	int ClientResult = client->Start(client_socket);
	//}

	// Use select() to check if there's a pending connection on ListenSocket
	// https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(ListenSocket, &readfds);
	timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	int select_result = select(0, &readfds, NULL, NULL, &timeout);
	if (select_result != SOCKET_ERROR && select_result != 0) {
		// Print select_result for debug
		printf("Select result: %d\n", select_result);

		printf("Incoming connection attempt...\n");

		// Create a new Client object to handle the connection

		// https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept
		// Accept incoming connection attempt
		client_socket = accept(ListenSocket, nullptr, nullptr);

		// Check if accept failed
		if (client_socket == INVALID_SOCKET) {
			printf("Failed to accept client connection: %d\n", WSAGetLastError());
			// Should not be a fatal error, just continue
		}
		// Create a new client object
		Client* client = new Client();
		// Add client to list of clients
		clients.push_back(client);
		// Start the client
		HRESULT handshake_result = client->Start(client_socket);

		if (handshake_result == SOCKET_ERROR) {
			printf("Handshake failed: %d\n", WSAGetLastError());
			// Remove client from list of clients
			clients.pop_back();
			// Delete client object
			delete client;
		}
	}
}

void Server::CheckForIncomingMessages()
{
	// Cycle through clients and check for incoming messages
	for (Client* client : clients) {
		if (client->IsMessagePending())
		{
			client->HandleIncomingMessage();
		}
	}
}
