#pragma once

#include "ntalpcapi.h"
#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <deque>
#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>

#pragma warning(disable:4200)

#pragma pack(1)

using CustomHeader = struct
{
	__int64 id_;			//message id
	int cmd_;				//command
	int total_len_;			//total length
	int len_;				//chunk len
	int chunk_count_;		//chunk index
	int chunk_offset;		//chunk offset
	unsigned char data_[0];
};

#pragma pack()

class AlpcBuffer
{
public:
	void PrepareSingle(const CustomHeader& h, const unsigned char* data, int len);
	void PrepareChunked(const CustomHeader& h, const unsigned char* data, int len);

	int GetCount();
	bool GetData(int index, std::vector<unsigned char>& data);

	void PushRaw(const std::vector<unsigned char>& raw);
private:
	std::vector<std::vector<unsigned char>> raw_msgs_;
};

#define ALPC_MAX_LEN		0xFFFF
#define ALPC_MAX_DATA_LEN	(ALPC_MAX_LEN - sizeof(PORT_MESSAGE))
#define ALPC_MAX_CUSTOM_PAYLOAD_LEN	(ALPC_MAX_DATA_LEN - sizeof(CustomHeader))

//iocp operation
enum
{
	IO_OP_READ,		//continue send_wait_reply
	IO_OP_EXIT,		//exit
};

using CustomPortContext = struct
{
	__int64		client_id{ -1LL };
	HANDLE		comm_port_handle{ NULL };
	//wchar_t		client_uuid[40] = { 0 };
	CLIENT_ID	process_info = { 0 };
};
