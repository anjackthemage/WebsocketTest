
#include "Client.h"

#include "ws2tcpip.h"
#include "stdio.h"
#include "iostream"
#include "bcrypt.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

Client::Client()
{
}

Client::~Client()
{
}

int Client::Start(SOCKET& InConnectSocket)
{
	if (InConnectSocket == INVALID_SOCKET) {
		printf("Invalid socket\n");
		return -1;
	}

	ConnectSocket = InConnectSocket;
	
	int iResult = 0;
	bool b_listen = true;
	char key_end[25];

	// Receive data until the client closes the connection
	do {
		// Receive data from the client
		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		printf("iResult: %d\n", iResult);
		b_listen = iResult == 0 ? false : true;
		if (iResult > 0) {
			printf("Bytes received: %d\n", iResult);

			// Print the received data
			printf("Received: %s\n", recvbuf);

			// Find Sec-WebSocket-Key header
			sec_websock_key = strstr(recvbuf, "Sec-WebSocket-Key");

			// Check if the header was found
			if (sec_websock_key == NULL) {
				printf("Sec-WebSocket-Key not found\n");
				goto quit;
			}
			else {
				// Extract the key
				char* key_start = sec_websock_key + 19;
				sscanf(key_start, "%s", key_end);
				printf("Sec-WebSocket-Key: %s\n", key_end);
				b_listen = false;
			}

		}
		else if (iResult == 0) {
			printf("Connection closing...\n");
		}
		else {
			printf("recv failed: %d\n", WSAGetLastError());
			goto quit;
		}
	} while (b_listen);

	// Concatenate the key with the magic string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	char magic_string[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	// Calculate the length of the new key
	size_t key_length = strlen(key_end) + strlen(magic_string);
	// Create a new buffer to hold the key and the magic string
	char* return_key = (char*)HeapAlloc(GetProcessHeap(), 0, key_length + 1);
	if (return_key == NULL) {
		printf("Memory allocation failed\n");
		goto quit;
	}
	// Copy the key to the new buffer
	strcpy(return_key, key_end);
	// Concatenate the magic string
	strcat(return_key, magic_string);

	// Now we encode the key using SHA1 and base64
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD cbData = 0,
		cbHash = 0,
		cbHashObject = 0;
	PBYTE pbHashObject = NULL;
	PBYTE pbHash = NULL;
	NTSTATUS status = 0;

	// Open an algorithm handle
	if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_SHA1_ALGORITHM,
		NULL,
		0))) {
		printf("BCryptOpenAlgorithmProvider failed with status: %d\n", status);
		goto quit;
	}

	// Calculate the size of the buffer to hold the hash object
	if (!BCRYPT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&cbHashObject,
		sizeof(DWORD),
		&cbData,
		0))) {
		printf("BCryptGetProperty failed with status: %d\n", status);
		goto quit;
	}

	// Allocate the hash object on the heap
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject) {
		printf("Memory allocation failed\n");
		goto quit;
	}

	// Create a hash
	if (!BCRYPT_SUCCESS(status = BCryptCreateHash(
		hAlg,
		&hHash,
		pbHashObject,
		cbHashObject,
		NULL,
		0,
		0))) {
		printf("BCryptCreateHash failed with status: %d\n", status);
		goto quit;
	}

	// Hash the data
	if (!BCRYPT_SUCCESS(status = BCryptHashData(
		hHash,
		(PBYTE)return_key,
		strlen(return_key),
		0))) {
		printf("BCryptHashData failed with status: %d\n", status);
		goto quit;
	}

	// Calculate the size of the hash
	if (!BCRYPT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(PBYTE)&cbHash,
		sizeof(DWORD),
		&cbData,
		0))) {
		printf("BCryptGetProperty failed with status: %d\n", status);
		goto quit;
	}

	// Allocate the hash buffer on the heap
	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash) {
		printf("Memory allocation failed\n");
		goto quit;
	}

	// Finish the hash
	if (!BCRYPT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHash,
		cbHash,
		0))) {
		printf("BCryptFinishHash failed with status: %d\n", status);
		goto quit;
	}

	// Base64 encode the hash
	DWORD base64_length = 0;
	if (!CryptBinaryToStringA(pbHash, cbHash, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64_length)) {
		printf("CryptBinaryToStringA failed with status: %d\n", GetLastError());
		goto quit;
	}

	char* base64_hash = (char*)HeapAlloc(GetProcessHeap(), 0, base64_length);

	if (!CryptBinaryToStringA(pbHash, cbHash, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64_hash, &base64_length)) {
		printf("CryptBinaryToStringA failed with status: %d\n", GetLastError());
		goto quit;
	}

	printf("Base64 hash: %s\n", base64_hash);

	// Build headers to send to the client
	char* response = (char*)HeapAlloc(GetProcessHeap(), 0, 1024);
	sprintf(response, "HTTP/1.1 101 Switching Protocols\r\n");
	sprintf(response, "%sSec-WebSocket-Accept: %s\r\n", response, base64_hash);
	sprintf(response, "%sConnection: Upgrade\r\n", response);
	sprintf(response, "%sUpgrade: websocket\r\n", response);
	sprintf(response, "%s\r\n", response);

	// Print the response
	printf("Sending response: %s\n", response);

	// Send the response to the client
	iResult = send(ConnectSocket, response, strlen(response), 0);
	if (iResult == SOCKET_ERROR) {
		printf("send failed: %d\n", WSAGetLastError());
		goto quit;
	}

	// Report successful connection
	printf("Response sent to client\n");

	// Wait for key press to exit
	//getchar();

	// Encode test message for websocket
	char* test_message = "Success!";
	char* encoded_message = (char*)HeapAlloc(GetProcessHeap(), 0, strlen(test_message) + 2);
	encoded_message[0] = 0x81;
	encoded_message[1] = strlen(test_message);
	strcpy(encoded_message + 2, test_message);

	// Send the message to the client
	iResult = send(ConnectSocket, encoded_message, strlen(test_message) + 2, 0);
	if (iResult == SOCKET_ERROR) {
		printf("send failed: %d\n", WSAGetLastError());
		goto quit;
	}

	// Report successful message
	printf("Message sent to client\n");

quit:

	return iResult;
}
