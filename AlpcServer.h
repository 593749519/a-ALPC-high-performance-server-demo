#pragma once

#include "AlpcPublic.h"

typedef VOID(NTAPI *PFN_RtlSetThreadWorkOnBehalfTicket)(PVOID);
typedef VOID(NTAPI* PFN_RtlClearThreadWorkOnBehalfTicket)();

class AlpcServer
{
public:
	DWORD Start(const std::wstring& port_name);
	void Stop();

private:
	void Dispatch();
	NTSTATUS DispatchInternal();

	PALPC_MESSAGE_ATTRIBUTES AllocMsgAttr();

	//iocp
	DWORD StartIoCompletion();
	DWORD PostIo(HANDLE port_handle, PVOID completion_key);
	void IoWorker();

	//message callback
	DWORD OnIncomingConnection(PPORT_MESSAGE msg_ptr, PALPC_MESSAGE_ATTRIBUTES msg_attr_ptr);
	DWORD OnReceiveMessage(PPORT_MESSAGE msg_ptr, PALPC_MESSAGE_ATTRIBUTES msg_attr_ptr);
	DWORD OnClientDisconnected(PPORT_MESSAGE msg_ptr, PALPC_MESSAGE_ATTRIBUTES msg_attr_ptr);
	DWORD OnConnectionComplete(PPORT_MESSAGE msg_ptr);

	HANDLE listen_handle_{ nullptr };
	std::vector<std::thread> io_threads_;
	std::atomic<int> run_flag_{ true };

	//port attribute of server
	ALPC_PORT_ATTRIBUTES port_attr_{ 0 };

	//default message attribute of server
	PALPC_MESSAGE_ATTRIBUTES msg_attr_ptr_{ nullptr };

	//port context for every client
	std::atomic<__int64> next_client_id_{ 0 };
	std::shared_mutex clients_lock_;
	std::map<__int64, std::unique_ptr<CustomPortContext>> port_contexts_;
	std::map<__int64, std::unique_ptr<ReassembleInfo>> reassemble_infos_;

	HANDLE iocp_handle_{ nullptr };

	PFN_RtlSetThreadWorkOnBehalfTicket set_work_on_behalf_func_{ nullptr };
	PFN_RtlClearThreadWorkOnBehalfTicket clear_work_on_behalf_func_{ nullptr };
};
