#pragma once

#include "AlpcPublic.h"

class AlpcClient
{
public:
	DWORD Start(const std::wstring& server_port_name, int tmo = 3000);
	void Stop();

	void PostData(int cmd, unsigned char* data, int len);

private:
	void Dispatch();

	PALPC_MESSAGE_ATTRIBUTES AllocMsgAttr();

	DWORD SendData(const std::vector<unsigned char>& data, int tmo = 10000);

	std::wstring server_port_name_;
	HANDLE port_handle_;
	std::thread dispatch_thread_;
	std::atomic<int> run_flag_{ true };

	std::mutex que_lock_;
	std::deque<std::unique_ptr<AlpcBuffer>> qued_bufs_;

	std::atomic<__int64> auto_inc_id_{ 0 };

	PALPC_MESSAGE_ATTRIBUTES msg_attr_ptr_{ false };

	ALPC_PORT_ATTRIBUTES port_attr_{ 0 };
	PVOID port_context_;

	std::vector<unsigned char> recv_buffer_;
};