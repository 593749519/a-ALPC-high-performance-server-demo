#include "AlpcServer.h"

//
DWORD AlpcServer::Start(const std::wstring& port_name)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES objPort = { 0 };
	UNICODE_STRING usPortName = { 0 };
	PSECURITY_DESCRIPTOR sd_ptr = NULL;		//parameterized later

	HMODULE module_handle = LoadLibrary(L"ntdll.dll");
	if (!module_handle)
	{
		return ::GetLastError();
	}
	set_work_on_behalf_func_ = (PFN_RtlSetThreadWorkOnBehalfTicket)GetProcAddress(module_handle, "RtlSetThreadWorkOnBehalfTicket");
	clear_work_on_behalf_func_ = (PFN_RtlClearThreadWorkOnBehalfTicket)GetProcAddress(module_handle, "RtlClearThreadWorkOnBehalfTicket");
	if (!set_work_on_behalf_func_ && clear_work_on_behalf_func_)
	{
		return ::GetLastError();
	}

	std::wstring prefixed_port_name = L"\\RPC Control\\" + port_name;

	RtlInitUnicodeString(&usPortName, prefixed_port_name.c_str());
	InitializeObjectAttributes(&objPort, &usPortName, 0, 0, sd_ptr);

	RtlSecureZeroMemory(&port_attr_, sizeof(port_attr_));
	port_attr_.Flags = ALPC_PORTFLG_WAITABLE_PORT | ALPC_PORTFLG_ALLOW_LPC_REQUESTS | ALPC_PORTFLG_ALLOWIMPERSONATION;
	port_attr_.SecurityQos.Length = sizeof(port_attr_.SecurityQos);
	port_attr_.SecurityQos.ImpersonationLevel = SecurityIdentification;
	port_attr_.SecurityQos.EffectiveOnly = TRUE;
	port_attr_.MaxMessageLength = ALPC_MAX_LEN;

	status = NtAlpcCreatePort(&listen_handle_, &objPort, &port_attr_);
	if (!NT_SUCCESS(status))
	{
		return RtlNtStatusToDosError(status);
	}

	return StartIoCompletion();
}

DWORD AlpcServer::PostIo(HANDLE port_handle, PVOID completion_key)
{
	HANDLE wait_handle = NULL;

	NTSTATUS status = NtCreateWaitCompletionPacket(&wait_handle, IO_COMPLETION_ALL_ACCESS, NULL);
	if (!NT_SUCCESS(status))
	{
		return RtlNtStatusToDosError(status);
	}

	BOOLEAN is_signaled = FALSE;
	status = NtAssociateWaitCompletionPacket(wait_handle, iocp_handle_, port_handle, completion_key, wait_handle, 0, NULL, &is_signaled);
	if (!NT_SUCCESS(status))
	{
		return RtlNtStatusToDosError(status);
	}

	return ERROR_SUCCESS;
}

void AlpcServer::IoWorker()
{
	while (run_flag_.load())
	{
		PVOID keyContext = NULL;
		PVOID apcContext = NULL;
		IO_STATUS_BLOCK ioStatus = { 0 };
		NTSTATUS status = NtRemoveIoCompletion(iocp_handle_, &keyContext, &apcContext, &ioStatus, NULL);
		if (NT_SUCCESS(status))
		{
			if (keyContext == (PVOID)IO_OP_EXIT)
			{
				break;
			}

			status = DispatchInternal();
			if (NT_SUCCESS(status))
			{
				//
			}

			if (apcContext)
			{
				NtClose((HANDLE)apcContext);
			}

			//trigger next io
			PostIo(listen_handle_, (PVOID)IO_OP_READ);
		}
	}
}

DWORD AlpcServer::StartIoCompletion()
{
	DWORD ret = ERROR_SUCCESS;

	if (!listen_handle_)
	{
		return ERROR_INVALID_HANDLE;
	}

	DWORD thread_count = 2;
	thread_count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
	if (thread_count < 8)
		thread_count = thread_count * 2;

	NTSTATUS status = NtCreateIoCompletion(&iocp_handle_, IO_COMPLETION_ALL_ACCESS, NULL, thread_count);
	if (!NT_SUCCESS(status))
	{
		return RtlNtStatusToDosError(status);
	}

	for (DWORD i = 0; i < thread_count; i++)
	{
		io_threads_.emplace_back(std::thread(std::bind(&AlpcServer::IoWorker, this)));
		//start io
		ret = PostIo(listen_handle_, (PVOID)IO_OP_READ);
	}

	return ret;
}

PALPC_MESSAGE_ATTRIBUTES AlpcServer::AllocMsgAttr()
{
	PALPC_MESSAGE_ATTRIBUTES attr_ptr = nullptr;
	ULONG64 attr_size = 0;

	NTSTATUS status = AlpcInitializeMessageAttribute(ALPC_MESSAGE_SECURITY_ATTRIBUTE | ALPC_MESSAGE_VIEW_ATTRIBUTE | ALPC_MESSAGE_CONTEXT_ATTRIBUTE | ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE, NULL, 0, &attr_size);
	if (!NT_SUCCESS(status) && status == STATUS_BUFFER_TOO_SMALL)
	{
		attr_ptr = (PALPC_MESSAGE_ATTRIBUTES)::malloc(attr_size);
		if (attr_ptr)
		{
			RtlSecureZeroMemory(attr_ptr, attr_size);
			status = AlpcInitializeMessageAttribute(ALPC_MESSAGE_SECURITY_ATTRIBUTE | ALPC_MESSAGE_VIEW_ATTRIBUTE | ALPC_MESSAGE_CONTEXT_ATTRIBUTE | ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE, attr_ptr, attr_size, &attr_size);
			if (!NT_SUCCESS(status))
			{
				::free(attr_ptr);
				attr_ptr = nullptr;
			}
		}
	}

	if (attr_ptr)
	{
		attr_ptr->ValidAttributes = ALPC_MESSAGE_CONTEXT_ATTRIBUTE | ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE;
	}

	return attr_ptr;
}

DWORD AlpcServer::OnIncomingConnection(PPORT_MESSAGE msg_ptr, PALPC_MESSAGE_ATTRIBUTES msg_attr_ptr)
{
	int total_len = msg_ptr->u1.s1.TotalLength;
	int data_len = msg_ptr->u1.s1.DataLength;

	HANDLE pid = msg_ptr->ClientId.UniqueProcess;
	HANDLE tid = msg_ptr->ClientId.UniqueThread;

	std::cout << "incoming pid=" << pid << ", tid=" << tid << std::endl;

	BOOL accept = TRUE;
	//validate something?
	//...

	HANDLE comm_port_handle = nullptr;
	std::unique_ptr<CustomPortContext> port_context = std::make_unique<CustomPortContext>();

	std::vector<unsigned char> conn_buf(sizeof(PORT_MESSAGE));
	PPORT_MESSAGE conn_msg_ptr = (PPORT_MESSAGE)&conn_buf[0];
	memcpy(conn_msg_ptr, msg_ptr, sizeof(PORT_MESSAGE));
	conn_msg_ptr->u2.s2.Type = LPC_CONNECTION_REPLY;
	conn_msg_ptr->u1.s1.DataLength = 0;
	conn_msg_ptr->u1.s1.TotalLength = sizeof(PORT_MESSAGE);

	NTSTATUS status = NtAlpcAcceptConnectPort(&comm_port_handle, listen_handle_, 0, NULL, &port_attr_, port_context.get(), conn_msg_ptr, NULL, accept);
	if (status == STATUS_PORT_DISCONNECTED || status == STATUS_REQUEST_CANCELED)
	{
		OnClientDisconnected(msg_ptr, nullptr);
	}
	else
	{
		std::unique_lock<std::shared_mutex> guard(clients_lock_);

		__int64 id = next_client_id_.fetch_add(1);
		port_context->client_id = id;
		port_context->comm_port_handle = comm_port_handle;
		port_context->process_info = msg_ptr->ClientId;
		port_contexts_[id] = std::move(port_context);
	}

	return status;
}

DWORD AlpcServer::OnReceiveMessage(PPORT_MESSAGE msg_ptr, PALPC_MESSAGE_ATTRIBUTES msg_attr_ptr)
{
	PALPC_CONTEXT_ATTR context_attr_ptr = (PALPC_CONTEXT_ATTR)AlpcGetMessageAttribute(msg_attr_ptr, ALPC_MESSAGE_CONTEXT_ATTRIBUTE);
	if (!context_attr_ptr)
		return ERROR_INVALID_PARAMETER;

	PVOID work_on_behalf_ptr = (PALPC_CONTEXT_ATTR)AlpcGetMessageAttribute(msg_attr_ptr, ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE);
	if (work_on_behalf_ptr && set_work_on_behalf_func_)
	{
		set_work_on_behalf_func_(work_on_behalf_ptr);
	}

	CustomPortContext* context_ptr = (CustomPortContext*)context_attr_ptr->PortContext;
	if (context_ptr)
	{
		CustomHeader* header_ptr = (CustomHeader*)(msg_ptr + 1);
		std::cout << "tid=" << GetCurrentThreadId() << ", custom message id=" << std::dec << header_ptr->id_ << ", comm port=" << context_ptr->comm_port_handle << std::endl;

		msg_ptr->u1.s1.DataLength = sizeof(CustomHeader);
		msg_ptr->u1.s1.TotalLength = sizeof(PORT_MESSAGE) + sizeof(CustomHeader);
		msg_ptr->u2.s2.Type = LPC_REPLY;
		msg_ptr->u2.s2.DataInfoOffset = 0;
		NTSTATUS status = NtAlpcSendWaitReceivePort(listen_handle_, ALPC_MSGFLG_RELEASE_MESSAGE, msg_ptr, NULL, NULL, NULL, NULL, NULL);
		if (!NT_SUCCESS(status))
		{
			std::cout << "send err=" << std::hex << status << std::endl;
		}
	}

	if (work_on_behalf_ptr && clear_work_on_behalf_func_)
	{
		clear_work_on_behalf_func_();
	}

	return ERROR_SUCCESS;
}

DWORD AlpcServer::OnClientDisconnected(PPORT_MESSAGE msg_ptr, PALPC_MESSAGE_ATTRIBUTES msg_attr_ptr)
{
	std::unique_lock<std::shared_mutex> guard(clients_lock_);

	if (msg_attr_ptr)
	{
		PALPC_CONTEXT_ATTR context_attr_ptr = (PALPC_CONTEXT_ATTR)AlpcGetMessageAttribute(msg_attr_ptr, ALPC_MESSAGE_CONTEXT_ATTRIBUTE);
		if (context_attr_ptr)
		{
			CustomPortContext* context_ptr = (CustomPortContext*)context_attr_ptr->PortContext;
			if (context_ptr)
			{
				std::cout << "gracefully disconnected, handle=" << context_ptr->comm_port_handle << ", pid=" << context_ptr->process_info.UniqueProcess << ", tid=" << context_ptr->process_info.UniqueThread << std::endl;
			}
		}
	}

	//remove client
	//...

	return ERROR_SUCCESS;
}

DWORD AlpcServer::OnConnectionComplete(PPORT_MESSAGE msg_ptr)
{
	std::cout << "abnormal connection, pid=" << msg_ptr->ClientId.UniqueProcess << ", tid=" << msg_ptr->ClientId.UniqueThread << std::endl;

	//remove client
	//...

	return ERROR_SUCCESS;
}

NTSTATUS AlpcServer::DispatchInternal()
{
	std::vector<unsigned char> recv_buf(16);

	PALPC_MESSAGE_ATTRIBUTES attr_ptr = AllocMsgAttr();

	SIZE_T len = 0;
	NTSTATUS status = NtAlpcSendWaitReceivePort(listen_handle_, 0, NULL, NULL, (PPORT_MESSAGE)&recv_buf[0], &len, NULL, NULL);
	if (status == STATUS_BUFFER_TOO_SMALL)
	{
		recv_buf.resize(len);
		status = NtAlpcSendWaitReceivePort(listen_handle_, 0, NULL, NULL, (PPORT_MESSAGE)&recv_buf[0], &len, attr_ptr, NULL);
	}
	else if (!NT_SUCCESS(status) || status == STATUS_TIMEOUT)
	{
		return status;
	}

	PPORT_MESSAGE msg_ptr = (PPORT_MESSAGE)&recv_buf[0];
	USHORT type = msg_ptr->u2.s2.Type & 0x0ff;
	switch (type)
	{
	case LPC_REQUEST:
		OnReceiveMessage((PPORT_MESSAGE)&recv_buf[0], attr_ptr);
		break;
	case LPC_REPLY:
		std::cout << "client reply" << std::endl;
		break;
	case LPC_DATAGRAM:
		std::cout << "datagram " << std::endl;
		break;
	case LPC_LOST_REPLY:
	case LPC_EXCEPTION:
	case LPC_DEBUG_EVENT:
	case LPC_ERROR_EVENT:
	case LPC_CANCELED:
		OnConnectionComplete((PPORT_MESSAGE)&recv_buf[0]);
		break;
	case LPC_PORT_CLOSED:
	case LPC_CLIENT_DIED:
		OnClientDisconnected((PPORT_MESSAGE)&recv_buf[0], attr_ptr);
		break;
	case LPC_CONNECTION_REQUEST:
		OnIncomingConnection((PPORT_MESSAGE)&recv_buf[0], attr_ptr);
		break;
	case LPC_CONNECTION_REPLY:
		//for server, don't process it
		break;
	}

	free(attr_ptr);

	return STATUS_SUCCESS;
}

void AlpcServer::Dispatch()
{
	for (;;)
	{
		if (!run_flag_.load())
		{
			break;
		}

		NTSTATUS status = DispatchInternal();
		if (!NT_SUCCESS(status))
		{
		}
	}
}

void AlpcServer::Stop()
{
	run_flag_.store(false);
	PostIo(iocp_handle_, (PVOID)IO_OP_EXIT);

	for (auto& thread : io_threads_)
	{
		if (thread.joinable())
		{
			thread.join();
		}
	}

	NtClose(iocp_handle_);
}