#include "AlpcPublic.h"

void AlpcBuffer::PrepareSingle(const CustomHeader& h, const unsigned char* data, int len)
{
	std::vector<unsigned char> packaged;
	int total_len = sizeof(PORT_MESSAGE) + sizeof(CustomHeader) + len;
	packaged.resize(total_len);

	PPORT_MESSAGE msg_ptr = (PPORT_MESSAGE)&packaged[0];

	msg_ptr->u1.s1.DataLength = (CSHORT)(total_len - sizeof(PORT_MESSAGE));
	msg_ptr->u1.s1.TotalLength = (CSHORT)total_len;
	msg_ptr->u2.s2.DataInfoOffset = 0;
	msg_ptr->u2.s2.Type = LPC_REQUEST;

	memcpy(msg_ptr + 1, &h, sizeof(CustomHeader));

	CustomHeader* header_ptr = (CustomHeader*)(msg_ptr + 1);
	header_ptr->total_len_ = len;
	header_ptr->chunk_count_ = 1;
	header_ptr->chunk_offset = 0;
	header_ptr->len_ = len;
	memcpy(header_ptr->data_, data, len);

	raw_msgs_.push_back(std::move(packaged));
}

void AlpcBuffer::PrepareChunked(const CustomHeader& h, const unsigned char* data, int len)
{
	int chunk_count = (len + ALPC_MAX_CUSTOM_PAYLOAD_LEN - 1) / ALPC_MAX_CUSTOM_PAYLOAD_LEN;
	for (int i = 0, chunk_index = 0; i < len; i += ALPC_MAX_CUSTOM_PAYLOAD_LEN, chunk_index++)
	{
		int chunk_len = ALPC_MAX_CUSTOM_PAYLOAD_LEN;
		if (len - i < ALPC_MAX_CUSTOM_PAYLOAD_LEN)
			chunk_len = len - i;

		std::vector<unsigned char> packaged;
		int message_len = sizeof(PORT_MESSAGE) + sizeof(CustomHeader) + chunk_len;
		packaged.resize(message_len);

		PPORT_MESSAGE msg_ptr = (PPORT_MESSAGE)&packaged[0];

		msg_ptr->u1.s1.DataLength = (CSHORT)(message_len - sizeof(PORT_MESSAGE));
		msg_ptr->u1.s1.TotalLength = (CSHORT)message_len;
		msg_ptr->u2.s2.DataInfoOffset = 0;
		msg_ptr->u2.s2.Type = LPC_REQUEST;

		memcpy(msg_ptr + 1, &h, sizeof(CustomHeader));

		CustomHeader* header_ptr = (CustomHeader*)(msg_ptr + 1);
		header_ptr->total_len_ = len;
		header_ptr->len_ = chunk_len;
		header_ptr->chunk_count_ = chunk_count;
		header_ptr->chunk_offset = i;
		memcpy(header_ptr->data_, data, chunk_len);

		raw_msgs_.push_back(std::move(packaged));
	}
}

//usually upon received message
void AlpcBuffer::PushRaw(const std::vector<unsigned char>& raw)
{
	raw_msgs_.push_back(std::move(raw));
}

int AlpcBuffer::GetCount()
{
	return (int)raw_msgs_.size();
}

bool AlpcBuffer::GetData(int index, std::vector<unsigned char>& data)
{
	if (index >= 0 && index < raw_msgs_.size())
	{
		data = raw_msgs_[index];
		return true;
	}

	return false;
}