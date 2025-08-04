#include "AlpcClient.h"

//
DWORD AlpcClient::Start(const std::wstring& server_port_name, int tmo)
{
	NTSTATUS status;
	ALPC_PORT_ATTRIBUTES portAttr = { 0 };
	OBJECT_ATTRIBUTES objPort = { 0 };
	UNICODE_STRING usPortName = { 0 };

	std::wstring prefixed_port_name = L"\\RPC Control\\" + server_port_name;
	server_port_name_ = prefixed_port_name;

	RtlInitUnicodeString(&usPortName, prefixed_port_name.c_str());
	InitializeObjectAttributes(&objPort, &usPortName, 0, 0, 0);

	RtlSecureZeroMemory(&port_attr_, sizeof(port_attr_));
	port_attr_.Flags = ALPC_PORTFLG_ALLOW_LPC_REQUESTS | ALPC_PORTFLG_ALLOWIMPERSONATION;
	port_attr_.SecurityQos.Length = sizeof(port_attr_.SecurityQos);
	port_attr_.SecurityQos.ImpersonationLevel = SecurityIdentification;
	port_attr_.SecurityQos.EffectiveOnly = TRUE;
	port_attr_.MaxMessageLength = ALPC_MAX_LEN;

	//default buffer to max size
	recv_buffer_.resize(ALPC_MAX_LEN);

	msg_attr_ptr_ = AllocMsgAttr();

	std::vector<unsigned char> data(sizeof(PORT_MESSAGE));
	PPORT_MESSAGE msg_ptr = (PPORT_MESSAGE)&data[0];
	msg_ptr->u1.s1.DataLength = 0;
	msg_ptr->u1.s1.TotalLength = sizeof(PORT_MESSAGE);

	LARGE_INTEGER conn_tmo = { 0 };
	conn_tmo.QuadPart = tmo;
	ULONG len = (ULONG)data.size();
	status = NtAlpcConnectPort(&port_handle_, &usPortName, NULL, &port_attr_, NULL, NULL, (PPORT_MESSAGE)&data[0], &len, msg_attr_ptr_, NULL, &conn_tmo);
	if (NT_SUCCESS(status))
	{
		PALPC_CONTEXT_ATTR context_attr_ptr = (PALPC_CONTEXT_ATTR)AlpcGetMessageAttribute(msg_attr_ptr_, ALPC_MESSAGE_CONTEXT_ATTRIBUTE);
		if (context_attr_ptr)
		{
			port_context_ = context_attr_ptr->PortContext;
		}

		dispatch_thread_ = std::thread(std::bind(&AlpcClient::Dispatch, this));
		return ERROR_SUCCESS;
	}
	else
	{
		return RtlNtStatusToDosError(status);
	}
}

void AlpcClient::Stop()
{
	run_flag_.store(false);
	if (dispatch_thread_.joinable())
	{
		dispatch_thread_.join();
	}

	if (port_handle_)
	{
		NtClose(port_handle_);
		port_handle_ = nullptr;
	}


	if (msg_attr_ptr_)
	{
		free(msg_attr_ptr_);
		msg_attr_ptr_ = nullptr;
	}
}

PALPC_MESSAGE_ATTRIBUTES AlpcClient::AllocMsgAttr()
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


void AlpcClient::PostData(int cmd, unsigned char* data, int len)
{
	std::unique_ptr<AlpcBuffer> buf_ptr = std::make_unique<AlpcBuffer>();

	CustomHeader h = { 0 };
	h.id_ = auto_inc_id_.fetch_add(1);
	h.cmd_ = cmd;
	buf_ptr->PrepareChunked(h, data, len);

	std::lock_guard<std::mutex> guard(que_lock_);
	qued_bufs_.push_back(std::move(buf_ptr));
}

DWORD AlpcClient::SendData(const std::vector<unsigned char>& data, int tmo)
{
	NTSTATUS status;
	LARGE_INTEGER default_recv_tmo = { 0 };

	SIZE_T len = recv_buffer_.size();
	default_recv_tmo.QuadPart = tmo;
	status = NtAlpcSendWaitReceivePort(port_handle_, 0, (PPORT_MESSAGE)&data[0], NULL, (PPORT_MESSAGE)&recv_buffer_[0], &len, msg_attr_ptr_, NULL); // &default_recv_tmo);
	if (!NT_SUCCESS(status))
	{
		std::cout << "send data err=" << std::hex << status << std::endl;
	}
	else
	{
		PPORT_MESSAGE msg_ptr = (PPORT_MESSAGE)&recv_buffer_[0];
		int type = msg_ptr->u2.s2.Type & 0xff;
		switch (type)
		{
		case LPC_REQUEST:
			std::cout << "server request" << std::endl;
			break;
		case LPC_REPLY:
			{
				CustomHeader* header_ptr = (CustomHeader*)(msg_ptr + 1);
				std::cout << "server reply, message id=" << header_ptr->id_ << std::endl;
			}
			break;
		default:
			std::cout << "unhandled request " << type << std::endl;
			break;
		}
	}
	return NT_SUCCESS(status) ? ERROR_SUCCESS : RtlNtStatusToDosError(status);
}

void AlpcClient::Dispatch()
{
	while (run_flag_.load())
	{
		std::unique_ptr<AlpcBuffer> alpc_buf;

		{
			std::lock_guard<std::mutex> guard(que_lock_);
			if (!qued_bufs_.empty())
			{
				alpc_buf = std::move(qued_bufs_.front());
				qued_bufs_.pop_front();
			}
		}

		if (alpc_buf)
		{
			bool all_ok = false;
			for (int i = 0; i < alpc_buf->GetCount(); i++)
			{
				std::vector<unsigned char> data;
				if (alpc_buf->GetData(i, data))
				{
					if (!run_flag_.load())
					{
						break;
					}

					DWORD ret = SendData(data);
					if (ret != ERROR_SUCCESS)
					{
						//
					}
				}
			}

			if (all_ok)
			{
				//
			}

			{
				std::lock_guard<std::mutex> guard(que_lock_);
				if (!qued_bufs_.empty())
					continue;
			}
		}
		else
		{
			//no sending, just receive
			LARGE_INTEGER tmo = { 0 };
			tmo.QuadPart = 1000;	//1s			
			SIZE_T recv_len = recv_buffer_.size();
			NTSTATUS status = NtAlpcSendWaitReceivePort(port_handle_, 0, NULL, NULL, (PPORT_MESSAGE)&recv_buffer_[0], &recv_len, msg_attr_ptr_, &tmo);
			if (!NT_SUCCESS(status))
			{
				break;
			}
			else if (status == STATUS_TIMEOUT)
			{
				Sleep(10);
				continue;
			}

			PPORT_MESSAGE msg_ptr = (PPORT_MESSAGE)&recv_buffer_[0];
			int lpc_type = msg_ptr->u2.s2.Type & 0xff;
			switch (lpc_type)
			{
			case LPC_CONNECTION_REPLY:
			{
				std::cout << "connected" << std::endl;
				break;
			}
			case LPC_REPLY:
			{
				CustomHeader* header_ptr = (CustomHeader*)(msg_ptr + 1);
				std::cout << "server reply, message id=" << std::dec << header_ptr->id_ << std::endl;
				break;
			}
			case LPC_REQUEST:
				std::cout << "server request" << std::endl;
				break;
			default:
				std::cout << "unhandled request " << lpc_type << std::endl;
			}
		}

		Sleep(10);
	}
}