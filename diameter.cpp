#include <cassert>
#include <iostream>

#include <cstdio>
#include <cstring>
#include <cstdlib>


#include "diameter.h"


using std::cerr;
using std::endl;


void Diameter::clear()
{
	for (auto it = avp_list.begin(); it != avp_list.end(); ++it)
	{
		it->clear();
	}
}


int Diameter::serialize_to_buffer(uint8_t* outbuffer, size_t max_length)
{
	assert(outbuffer);
	assert(max_length > DIAMETER_HEADER_LENGTH);
	assert(avp_list.size() > 0);

	size_t pos = 0;
	int result = header.serialize_header_to_buffer(outbuffer, max_length);
	if (!result)
	{
		cerr << "serialize header FAILED." << endl;
		return -1;
	}
	pos += DIAMETER_HEADER_LENGTH;

	//serialize body.
	vector<Avp>::iterator it;
	for (it = avp_list.begin(); it != avp_list.end(); ++it) 
	{
		if ((pos + DIAMETER_AVP_MIN_LENGTH) > max_length)
		{
			cerr << "buffer to small." << endl;
			return -1;
		}
		
		int length = it->serialize_to_buffer(outbuffer + pos, max_length - pos);
		if (length <= 0)
		{
			cerr << "serialize avp failed." << endl;
			return -1;
		}

		pos += length;
	}

	//修正包总长度？
	uint32_t endian_value = CONVERT_UINT32(pos);
	memcpy(outbuffer + 1, (char*)&endian_value + 1, 3);
	return pos;
}


int Diameter::parse_from_buffer(uint8_t* inbuffer, size_t in_length)
{
	assert(inbuffer);
	assert(in_length > DIAMETER_HEADER_LENGTH);
	//已经有数据的Diameter不再允许反序列化；
	assert(avp_list.size() == 0);
	size_t pos = 0;
	//开始
	if (header.parse_diameter_header(inbuffer) != 0)
	{
		cerr << "parse diameter header failed." << endl;
		return -1;
	}
	pos += DIAMETER_HEADER_LENGTH;

	while (true)
	{
		if ((pos + DIAMETER_AVP_MIN_LENGTH) > in_length)
		{
			break;
		}
		Avp avp;
		int cur_length = Avp::extract_one_avp(inbuffer + pos, in_length - pos, avp);
		if (cur_length <= 0)
		{
			break;
		}
		avp_list.push_back(avp);
		pos += cur_length;
	}

	return pos;
}


void Diameter::dump() const
{
	header.dump_header();
	AVPListConstIter it;
	for (it = avp_list.begin(); it != avp_list.end(); ++it)
	{
		it->dump_avp();
	}
}


int Diameter::extract_spec_avp(uint32_t avp_code, Avp& out)
{
	AVPListIter it;
	for (it = avp_list.begin(); it != avp_list.end(); ++it)
	{
		if (it->code == avp_code)
		{
			out = *it;
			return 0;
		}
	}

	return -1;
}


int Diameter::extract_spec_as_uint32(uint32_t avp_code, uint32_t& out)
{
	Avp temp_avp;

	int length = extract_spec_avp(avp_code, temp_avp);
	if (length == -1)
	{
		cerr << "extract spec avp failed: " << avp_code << endl;
		return -1;
	}
	return temp_avp.data_to_uint32(out);
}


int Diameter::extract_spec_as_str(uint32_t avp_code, string& out)
{
	Avp temp_avp;

	int length = extract_spec_avp(avp_code, temp_avp);
	if (length < 0)
	{
		return -1;
	}

	return temp_avp.data_to_string(out);
}


int Diameter::extract_spec_as_buf(uint32_t avp_code, uint8_t* outbuffer, size_t in_length)
{
	assert(outbuffer);
	Avp temp_avp;

	int length = extract_spec_avp(avp_code, temp_avp);
	if (length < 0)
	{
		return -1;
	}

	return temp_avp.data_to_buffer(outbuffer, in_length);
}


int DiameterHeader::parse_diameter_header(uint8_t* buffer)
{
	assert(buffer);
	int pos = 0;
	//第一字节一定得为1
	version = buffer[pos];
	if (version != 1)
	{
		cerr << "Diameter protocol error." << endl;
		return -1;
	}
	pos += 1;

	//假设端序一致的情况下
	//length
	memcpy((char*)&length + 1, buffer + pos, 3);
	length = CONVERT_UINT32(length);
	pos += 3;

	//flags
	flags.flags_value = buffer[pos];
	pos += 1;

	//command code
	memcpy((char*)&code + 1, buffer + pos, 3);
	code = CONVERT_UINT32(code);
	pos += 3;

	//application id
	memcpy((char*)&application_id, buffer + pos, 4);
	application_id = CONVERT_UINT32(application_id);
	pos += 4;

	//hop-by-hop
	memcpy((char*)&hop_by_hop, buffer + pos, 4);
	hop_by_hop = CONVERT_UINT32(hop_by_hop);
	pos += 4;

	//end to end;
	memcpy((char*)&end_to_end, buffer + pos, 4);
	end_to_end = CONVERT_UINT32(end_to_end);
	pos += 4;

	assert(pos == DIAMETER_HEADER_LENGTH);
	return 0;
}


int DiameterHeader::serialize_header_to_buffer(uint8_t* out_buffer, size_t max_length)
{
	unused_for_compile(max_length);
	assert(out_buffer);
	assert(max_length >= DIAMETER_HEADER_LENGTH);
	assert(length < DIAMETER_MAX_LENGTH);

	int pos = 0;
	uint32_t endian_value = 0;
	
	//version
	out_buffer[pos] = version;
	pos += 1;

	//length
	endian_value = CONVERT_UINT32(length);
	memcpy(out_buffer + pos, (char*)&endian_value + 1, 3);
	pos += 3;

	//flags
	out_buffer[pos] = flags.flags_value;
	pos += 1;

	//code
	endian_value = CONVERT_UINT32(code);
	memcpy(out_buffer + pos, (char*)&endian_value + 1, 3);
	pos += 3;

	//application id
	endian_value = CONVERT_UINT32(application_id);
	memcpy(out_buffer + pos, (char*)&endian_value, 4);
	pos += 4;

	//hop by hop
	endian_value = CONVERT_UINT32(hop_by_hop);
	memcpy(out_buffer + pos, (char*)&endian_value, 4);
	pos += 4;

	//end to end;
	endian_value = CONVERT_UINT32(end_to_end);
	memcpy(out_buffer + pos, (char*)&endian_value, 4);
	pos += 4;

	assert(pos == DIAMETER_HEADER_LENGTH);
	return DIAMETER_HEADER_LENGTH;
}


void DiameterHeader::dump_header() const
{
	printf("============HEADER============\n");
	printf("%-18s%u\n", "version", version);
	printf("%-18s%u\n", "length", length);
	printf("%-18s%u\n", "R", flags.flag_r ? 1 : 0);
	printf("%-18s%u\n", "P", flags.flag_p ? 1 : 0);
	printf("%-18s%u\n", "E", flags.flag_e ? 1 : 0);
	printf("%-18s%u\n", "T", flags.flag_t ? 1 : 0);
	printf("%-18s%u\n", "code", code);
	printf("%-18s%u\n", "app_id", application_id);
	printf("%-18s%u\n", "hop-by-hop", hop_by_hop);
	printf("%-18s%u\n", "end-to-end", end_to_end);
	printf("************HEADER************\n");
}


void Avp::clear()
{
	data.clear();
}


int Avp::serialize_to_buffer(uint8_t* out_buffer, size_t in_length)
{
	unused_for_compile(in_length);
	assert(out_buffer);
	assert(in_length > DIAMETER_AVP_MIN_LENGTH);
	//必须已对齐，在set value时必须对齐
	assert(data.size() % 4 == 0);
	int pos = 0;
	int endian_value = 0;

	// avp code
	endian_value = CONVERT_UINT32(code);
	memcpy(out_buffer + pos, (char*)&endian_value, 4);
	pos += 4;

	//flags
	out_buffer[pos] = flags.flags_value;
	pos += 1;

	//avp length
	if (flags.flag_v)
	{
		//length = data.size() + 12;
		length = realy_data_length + 12;
	}
	else
	{
		//length = data.size() + 8;
		length = realy_data_length + 8;
	}
	endian_value = CONVERT_UINT32(length);
	memcpy(out_buffer + pos, (char*)&endian_value + 1, 3);
	pos += 3;

	//vendor id
	if (flags.flag_v)
	{
		endian_value = CONVERT_UINT32(vendor_id);
		memcpy(out_buffer + pos, (char*)&endian_value, 4);
		pos += 4;
	}

	//left data; vector 一定连续
	size_t i;
	for (i = 0; i < data.size(); i++)
	{
		out_buffer[pos] = data[i];
		pos += 1;
	}
	return pos;
}


/*
从一个buffer中拆出一个avp
返回0，无avp
返回-1，错误
返回大于0，即avp用掉的buffer，剩余内容可继续调用此函数；
out 为输出
*/
int Avp::extract_one_avp(uint8_t* in_buffer, size_t in_length, Avp& out)
{
	assert(in_buffer);
	if (in_length < DIAMETER_AVP_MIN_LENGTH)
	{
		return 0;
	}

	Avp temp_avp;

	size_t pos = 0;

	//code
	memcpy((char*)&temp_avp.code, in_buffer + pos, 4);
	temp_avp.code = CONVERT_UINT32(temp_avp.code);
	pos += 4;

	//flags
	temp_avp.flags.flags_value = in_buffer[pos];
	pos += 1;

	//length
	memcpy((char*)&temp_avp.length + 1, in_buffer + pos, 3);
	temp_avp.length = CONVERT_UINT32(temp_avp.length);
	if (temp_avp.flags.flag_v)
	{
		temp_avp.realy_data_length = temp_avp.length - 12;
	}
	else
	{
		temp_avp.realy_data_length = temp_avp.length - 8;
	}
	pos += 3;

	assert(temp_avp.length <= DIAMETER_MAX_LENGTH);

	// vendor id
	if (temp_avp.flags.flag_v)
	{
		memcpy((char*)&temp_avp.vendor_id, in_buffer + pos, 4);
		temp_avp.vendor_id = CONVERT_UINT32(temp_avp.vendor_id);
		pos += 4;
	}

	//data
	int data_length = temp_avp.length - pos;
	if (data_length % 4)
	{
		data_length += 4 - data_length % 4;
	}

	if ((pos + data_length) > in_length)
	{
		return 0;
	}

	int i;
	uint8_t* data_buffer = in_buffer + pos;
	for (i = 0; i != data_length; ++i)
	{
		temp_avp.data.push_back(data_buffer[i]);
	}
	pos += data_length;
	out = temp_avp;

	return pos;
}


int Avp::data_to_buffer(uint8_t* in_buffer, size_t in_length)
{
	assert(in_buffer);
	size_t i;

	if ((data.size() + 1) > in_length)
	{
		return -1;
	}

	for (i = 0; i < data.size(); i++)
	{
		in_buffer[i] = data[i];
	}

	return data.size();
}


int Avp::data_to_string(string& out)
{
	char* buf = (char*)malloc(data.size() + 1);
	if (!buf)
	{
		cerr << "malloc error." << endl;
		return -1;
	}

	size_t i;
	for (i = 0; i < data.size(); i++)
	{
		buf[i] = data[i];
	}
	buf[data.size()] = 0;
	out.assign(buf);
	free(buf);
	return out.size();
}


int Avp::data_to_uint32(uint32_t& out)
{
	if (data.size() != sizeof(uint32_t))
	{
		return -1;
	}
	size_t i;
	for (i = 0; i < sizeof(uint32_t); i++)
	{
		((char*)&out)[i] = data[i];
	}

	out = CONVERT_UINT32(out);
	return sizeof(out);
}


static string hex_dump_vec_char(vector<uint8_t> buffer)
{
	size_t i;
	string out;
	char hexbuf[4];

	for (i = 0; i != buffer.size(); ++i)
	{
		memset(hexbuf, 0, sizeof(hexbuf));
		sprintf(hexbuf, "%02X", (unsigned char)buffer[i]);
		out += hexbuf;
		out += " ";
	}
	return out;
}


string vec_char_to_str(vector<uint8_t> buffer)
{
	return string(buffer.begin(), buffer.end());
}


void Avp::dump_avp() const
{
	printf("============AVP============\n");
	printf("%-18s%u\n", "code", code);
	printf("%-18s%u\n", "V", flags.flag_v ? 1 : 0);
	printf("%-18s%u\n", "M", flags.flag_m ? 1 : 0);
	printf("%-18s%u\n", "P", flags.flag_p ? 1 : 0);
	printf("%-18s%u\n", "length", length);
	if (flags.flag_v)
	{
		printf("%-18s%u\n", "vendor id", vendor_id);
	}
	printf("%-18s%" SIZE_FMT "\n", "data size", data.size());
	printf("%-18s[%s][%s]\n", "data", hex_dump_vec_char(data).c_str(), vec_char_to_str(data).c_str());
	printf("************AVP************\n");
}


void Avp::set_avp_info(uint32_t code, uint8_t hasVendorId, uint8_t isNeed, uint8_t isEncrypt)
{
	assert(hasVendorId == 0 || hasVendorId == 1);
	assert(isNeed == 0 || isNeed == 1);
	assert(isEncrypt == 0 || isEncrypt == 1);

	this->code = code;
	this->flags.flag_v = hasVendorId;
	this->flags.flag_m = isNeed;
	this->flags.flag_p = isEncrypt;
}


void Avp::set_avp_vendorid(uint32_t vendor_id)
{
	assert(this->flags.flag_v == 1);
	this->vendor_id = vendor_id;
}


void Avp::set_avp_data(const uint8_t* buffer, size_t length)
{
	assert(length < DIAMETER_MAX_LENGTH);
	//必须是空的，禁止设置第二次！！！！
	assert(data.size() == 0);
	
	realy_data_length = length;

	size_t i;
	for (i = 0; i < length; i++)
	{
		data.push_back(buffer[i]);
	}

	if (length % 4)
	{
		size_t zero_length = 4 - length % 4;
		for (i = 0; i < zero_length; i++)
		{
			data.push_back(0);
		}
	}
}


void Avp::set_str_avp(uint32_t code, uint8_t flags, const string& _data)
{
	this->set_avp_info(code, 0, 0, 0);
	this->flags.flags_value = flags;
	this->set_avp_data((const uint8_t*)_data.c_str(), _data.size());
}


void Avp::set_int_avp(uint32_t code, uint8_t flags, uint32_t value)
{
	this->set_avp_info(code, 0, 0, 0);
	this->flags.flags_value = flags;
	uint32_t endian_value = CONVERT_UINT32(value);
	this->set_avp_data((const uint8_t*)&endian_value, sizeof(uint32_t));
}


void Avp::set_buf_avp(uint32_t code, uint8_t flags, uint8_t* buffer, size_t length)
{
	this->set_avp_info(code, 0, 0, 0);
	this->flags.flags_value = flags;
	this->set_avp_data(buffer, length);
}


Avp Avp::from_str(uint32_t code, uint8_t flags, const string& data)
{
	Avp out;
	out.set_str_avp(code, flags, data);
	return out;
}


Avp Avp::from_int(uint32_t code, uint8_t flags, uint32_t value)
{
	Avp out;
	out.set_int_avp(code, flags, value);
	return out;
}


Avp Avp::from_buf(uint32_t code, uint8_t flags, uint8_t* buffer, size_t length)
{
	Avp out;
	out.set_buf_avp(code, flags, buffer, length);
	return out;
}


void Avp::get_grouped(vector<Avp>& out)
{
	char* buf = (char*)malloc(realy_data_length + 1);

	if (!buf)
	{
		cerr << "malloc error!" << endl;
		return;
	}

	//copy(data.begin(), data.end(), buf);
	for (size_t i = 0; i != data.size(); ++i)
	{
		buf[i] = data[i];
	}
	
	int pos = 0;
	while (true)
	{
		Avp avp;
		int result;
		result = extract_one_avp((uint8_t*)(buf + pos), realy_data_length - pos, avp);
		if (result <= 0)
		{
			break;
		}

		pos += result;
		out.push_back(avp);
	}

	free(buf);
}
