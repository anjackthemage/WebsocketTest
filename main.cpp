
#include "Server.h"
#include "string"
#include "iostream"
#include "algorithm"
#include "thread"
#include "Client.h"

void StartServer(Server* server)
{
	// Start the server
	server->Start();
	server->ListenForIncomingConnections();
}

// Print the help message
void PrintHelpMessage()
{
	std::cout << "Available commands:" << std::endl;
	std::cout << "exit - Exit the program" << std::endl;
	std::cout << "clients - Print the number of connected clients" << std::endl;
}

int main()
{
	// Exit code
	int exit_code = 0;

	printf("Starting server...\n");

	// Start the server
	Server* server = new Server();
	std::thread server_thread(StartServer, server);

	// String to hold typed commands.
	std::string command;

	// Print the help message
	PrintHelpMessage();

	while (true)
	{
		// Wait for user to type commands
		std::cin >> command;

		// Convert command to lowercase for easy parsing
		std::transform(command.begin(), command.end(), command.begin(), ::tolower);

		// Switch on the command
		if (command == "exit")
		{
			// Stop the server
			server->Stop();

			// Exit the program
			break;
		}
		else if (command == "clients")
		{
			// Print the number of connected clients
			std::cout << "Connected clients: " << server->clients.size() << std::endl;
		}
		else if (command == "help")
		{
			// Print the help message
			PrintHelpMessage();
		}
		else
		{
			// Send the text to all connected clients
			for (Client* client : server->clients)
			{
				// Encode the message
				char* encoded_message = (char*)HeapAlloc(GetProcessHeap(), 0, command.length() + 2);
				encoded_message[0] = 0x81;
				encoded_message[1] = command.length();
				strcpy(encoded_message + 2, command.c_str());
				// Send the message to the client
				int iResult = send(client->ConnectSocket, encoded_message, strlen(encoded_message), 0);
				if (iResult == SOCKET_ERROR) {
					printf("send failed: %d\n", WSAGetLastError());
					break;
				}
			}
		}
	}

	// Clean up
	server_thread.join();
	delete server;

	return exit_code;
}

