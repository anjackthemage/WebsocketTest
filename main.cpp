
#include "Server.h"
#include "string"
#include "iostream"
#include "algorithm"
#include "thread"

void StartServer(Server* server)
{
	// Start the server
	server->Start();
	server->ListenForIncomingConnections();
}

int main()
{
	// Exit code
	int exit_code = 0;

	printf("Starting server...\n");

	// Start the server
	Server* server = new Server();
	std::thread server_thread(StartServer, server);

	while (true)
	{
		// Wait for user to type commands
		std::string command;
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
		else
		{
			// Print the help message
			std::cout << "Available commands:" << std::endl;
			std::cout << "exit - Exit the program" << std::endl;
			std::cout << "clients - Print the number of connected clients" << std::endl;
		}
	}

	// Clean up
	server_thread.join();
	delete server;

	return exit_code;
}

