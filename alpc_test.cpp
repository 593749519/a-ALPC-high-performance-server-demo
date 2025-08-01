#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tchar.h>
#include <iostream>

#include "AlpcServer.h"
#include "AlpcClient.h"

enum
{
	TEST_CMD_PING,
	TEST_CMD_BYE,
};

int _tmain(int argc, _TCHAR* argv[])
{
	AlpcServer server;
	AlpcClient client1, client2;

	DWORD ret = server.Start(std::wstring(L"test_alpc"));
	if (ret != ERROR_SUCCESS)
	{
		std::cout << "Failed to start server" << std::endl;
		return -1;
	}

	std::vector<std::unique_ptr<AlpcClient>> clients;

	//create clients
	for (int i = 0; i < 100; i++)
	{
		std::unique_ptr<AlpcClient> client = std::make_unique<AlpcClient>();
		if (ERROR_SUCCESS != client->Start(std::wstring(L"test_alpc")))
		{
			std::cout << "Failed to start client " << i << std::endl;
		}
		clients.emplace_back(std::move(client));
	}

	//wait some time for clients' thread to start
	::Sleep(3000);

	//post data
	for (int i = 0; i < 1000; i++)
	{
		for (auto& client : clients)
		{
			//arbitary data
			std::vector<unsigned char> data(ALPC_MAX_CUSTOM_PAYLOAD_LEN);

			client->PostData(TEST_CMD_PING, (unsigned char*)&data, sizeof(data));
		}
	}

	::Sleep(3000);

	//close clients
	{
		for (auto& client : clients)
		{
			client->Stop();
		}
	}

	server.Stop();

	Sleep(INFINITE);

	return 0;
}