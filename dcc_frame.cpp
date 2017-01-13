#include "dcc_frame.h"

// for inet_aton
#ifdef WIN32
/*#include <WinSock2.h>*/
#include <Ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

//获取时间戳
#include <time.h>  
#ifdef WIN32  
#include <sys/timeb.h>  
#else  
#include <sys/time.h>  
#endif

#include <iostream>
#include <map>
#include <stdio.h>

#include <cstring>
#include <cstdlib>
#include <cstdio>

#include <cassert>

//1900年1月1日至1970年的秒数，时间戳+这个值，等于 Diameter需要的值
#define SECONDS 2208988800


using namespace std;


int DisconnectPeerRequest::deserialize(const uint8_t* in_buffer, size_t buf_length)
{
	unused_for_compile(in_buffer);
	unused_for_compile(buf_length);
	throw std::logic_error("The method or operation is not implemented.");
}


int DisconnectPeerRequest::serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence)
{
	CHECK_STRING_FIELD_RETURN(origin_host, -1);
	CHECK_STRING_FIELD_RETURN(origin_realm, -1);

	header.version = 1;
	header.code = CODE_DPR;
	header.flags.flag_r = 1;
	header.hop_by_hop = sequence;
	header.end_to_end = sequence;

	CHECK_STRING_FIELD_RETURN(origin_host, -1);
	CHECK_STRING_FIELD_RETURN(origin_realm, -1);

	add_avp(Avp::from_str(avp_origin_host, AVP_FLAGS_NECESSARY, origin_host));
	add_avp(Avp::from_str(avp_origin_realm, AVP_FLAGS_NECESSARY, origin_realm));
	add_avp(Avp::from_int(avp_disconnect_cause, AVP_FLAGS_NECESSARY, disconnect_cause));
	return serialize_to_buffer(out_buffer, buf_length);
}


int CapabilitiesExchangeRequest::deserialize(const uint8_t* in_buffer, size_t buf_length)
{
	unused_for_compile(in_buffer);
	unused_for_compile(buf_length);

	throw std::logic_error("The method or operation is not implemented.");
}


/*
使用场景
CapabilitiesExchangeRequest cer;
cer.origin_host = "";
cer.xx =xx ;
cer.yyy = yyyyyy;
cer.serialize(buf, sizeof(buf));
*/
int CapabilitiesExchangeRequest::serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence)
{
	header.version = 1;
	header.code = CODE_CER;
	header.flags.flag_r = 1;
	header.hop_by_hop = sequence;
	header.end_to_end = sequence;

	CHECK_STRING_FIELD_RETURN(origin_host, -1);
	CHECK_STRING_FIELD_RETURN(origin_realm, -1);

	add_avp(Avp::from_str(avp_origin_host, AVP_FLAGS_NECESSARY, origin_host));
	add_avp(Avp::from_str(avp_origin_realm, AVP_FLAGS_NECESSARY, origin_realm));
	
	//协议两字节 0x00，0x01，IP地址4字节；
	uint8_t buf[sizeof(uint16_t) + sizeof(in_addr)];
	memset(buf, 0, sizeof(buf));
	*(((uint16_t*)(void*)buf)) = CONVERT_UINT16(1);//协议取值1
	inet_pton(AF_INET, host_ip_address.c_str(), buf + sizeof(uint16_t));
	add_avp(Avp::from_buf(avp_host_ip_address, AVP_FLAGS_NECESSARY, buf, sizeof(buf)));

	add_avp(Avp::from_int(avp_vendor_id, AVP_FLAGS_NECESSARY, vendor_id));

	if (!product_name.empty())
	{
		add_avp(Avp::from_str(avp_product_name, AVP_FLAGS_UNNECESSARY, product_name));
	}
	add_avp(Avp::from_int(avp_origin_state_id, AVP_FLAGS_NECESSARY, origin_state_id));
	add_avp(Avp::from_int(avp_supported_vendor_id, AVP_FLAGS_NECESSARY, supported_vendor_id));
	add_avp(Avp::from_int(avp_auth_application_id, AVP_FLAGS_NECESSARY, auth_application_id));
	add_avp(Avp::from_int(avp_acct_application_id, AVP_FLAGS_NECESSARY, acct_application_id));
	add_avp(Avp::from_int(avp_inband_security_id, AVP_FLAGS_NECESSARY, inband_security_id));
	add_avp(Avp::from_int(avp_firmware_revision, AVP_FLAGS_UNNECESSARY, firmware_revision));

	return serialize_to_buffer(out_buffer, buf_length);
}


int DeviceWatchdogRequest::deserialize(const uint8_t* in_buffer, size_t buf_length)
{
	//do nothing...
	unused_for_compile(in_buffer);
	unused_for_compile(buf_length);

	return 0;
}


int DeviceWatchdogRequest::serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence)
{
	CHECK_STRING_FIELD_RETURN(origin_host, -1);
	CHECK_STRING_FIELD_RETURN(origin_realm, -1);

	header.version = 1;
	header.code = CODE_DWR;
	header.flags.flag_r = 1;
	header.hop_by_hop = sequence;
	header.end_to_end = sequence;

	add_avp(Avp::from_str(avp_origin_host, AVP_FLAGS_NECESSARY, origin_host));
	add_avp(Avp::from_str(avp_origin_realm, AVP_FLAGS_NECESSARY, origin_realm));

	return serialize_to_buffer(out_buffer, buf_length);
}


int CreditControlRequest::deserialize(const uint8_t* in_buffer, size_t buf_length)
{
	unused_for_compile(in_buffer);
	unused_for_compile(buf_length);

	throw std::logic_error("The method or operation is not implemented.");
}


int CreditControlRequest::serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence)
{
	CHECK_STRING_FIELD_RETURN(origin_host, -1);
	CHECK_STRING_FIELD_RETURN(origin_realm, -1);

	header.version = 1;
	header.application_id = 4;
	header.code = CODE_CCR;
	header.flags.flag_r = 1;
	header.flags.flag_p = 1;
	header.hop_by_hop = sequence;
	header.end_to_end = sequence;
	uint32_t timestamp_since_1900 = event_timestamp + SECONDS;

	char buf_timestamp[128];
	char buf_sequence[128];

	memset(buf_timestamp, 0, sizeof(buf_timestamp));
	memset(buf_sequence, 0, sizeof(buf_sequence));

	sprintf(buf_timestamp, ";%u", timestamp_since_1900);
	sprintf(buf_sequence, ";%u", header.hop_by_hop);

	assert(session_id == "");
	session_id = "";
	session_id += origin_host;
	session_id += buf_timestamp;
	session_id += buf_sequence;

	add_avp(Avp::from_str(avp_session_id, AVP_FLAGS_NECESSARY, session_id));
	add_avp(Avp::from_str(avp_origin_host, AVP_FLAGS_NECESSARY, origin_host));
	add_avp(Avp::from_str(avp_origin_realm, AVP_FLAGS_NECESSARY, origin_realm));
	add_avp(Avp::from_str(avp_destination_host, AVP_FLAGS_NECESSARY, destination_host));
	add_avp(Avp::from_str(avp_destination_realm, AVP_FLAGS_NECESSARY, destination_realm));
	add_avp(Avp::from_int(avp_auth_application_id, AVP_FLAGS_NECESSARY, auth_application_id));
	add_avp(Avp::from_str(avp_service_context_id, AVP_FLAGS_NECESSARY, service_context_id));
	add_avp(Avp::from_int(avp_cc_request_type, AVP_FLAGS_NECESSARY, cc_request_type));
	add_avp(Avp::from_int(avp_cc_request_number, AVP_FLAGS_NECESSARY, cc_request_number));
	add_avp(Avp::from_int(avp_event_timestamp, AVP_FLAGS_NECESSARY, timestamp_since_1900));

	//group subscription id begin
	uint8_t subscription_id_buf[128];
	memset(subscription_id_buf, 0, sizeof(subscription_id_buf));
	Avp subscription_id_type_avp_obj = Avp::from_int(avp_subscription_id_type, AVP_FLAGS_NECESSARY, subscription_id_type);
	Avp subscription_id_data_avp_obj = Avp::from_str(avp_subscription_id_data, AVP_FLAGS_NECESSARY, subscription_id_data);

	int result = 0;
	int length = 0;

	result = subscription_id_type_avp_obj.serialize_to_buffer(subscription_id_buf, sizeof(subscription_id_buf));
	if (result <= 0)
	{
		cerr << "subscription id type serialize failed." << endl;
		return -1;
	}
	length += result;

	result = subscription_id_data_avp_obj.serialize_to_buffer(subscription_id_buf + length, sizeof(subscription_id_buf) - length);
	if (length <= 0)
	{
		cerr << "subscription id data serialize failed." << endl;
		return -1;
	}
	length += result;

	add_avp(Avp::from_buf(avp_subscription_id, AVP_FLAGS_NECESSARY, subscription_id_buf, length));
	//group subscription id end;

	add_avp(Avp::from_int(avp_requested_action, AVP_FLAGS_NECESSARY, requested_action));
	add_avp(Avp::from_int(avp_service_identifier, AVP_FLAGS_NECESSARY, service_identifier));


	//三层group
	uint8_t service_information_buf[1024];
	memset(service_information_buf, 0, sizeof(service_information_buf));

	//首先处理最底层
	length = 0;
	Avp service_type_avp_obj = Avp::from_str(avp_service_type, AVP_FLAGS_NECESSARY, service_type);
	result = service_type_avp_obj.serialize_to_buffer(service_information_buf + length, sizeof(service_information_buf) - length);
	if (result <= 0)
	{
		cerr << "service_type_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	//逐个序列化到buffer中
	Avp transactionid_avp_obj = Avp::from_str(avp_transactionid, AVP_FLAGS_UNNECESSARY, transactionid);
	result = transactionid_avp_obj.serialize_to_buffer(service_information_buf + length, sizeof(service_information_buf) - length);
	if (result <= 0)
	{
		cerr << "transactionid_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	Avp trade_time_avp_obj = Avp::from_str(avp_trade_time, AVP_FLAGS_NECESSARY, trade_time);
	result = trade_time_avp_obj.serialize_to_buffer(service_information_buf + length, sizeof(service_information_buf) - length);
	if (result <= 0)
	{
		cerr << "trade_time_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	Avp serialno_avp_obj = Avp::from_str(avp_serialno, AVP_FLAGS_NECESSARY, serialno);
	result = serialno_avp_obj.serialize_to_buffer(service_information_buf + length, sizeof(service_information_buf) - length);
	if (result <= 0)
	{
		cerr << "serialno_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	int flags_old_serialno;
	if (oldserialno.empty()) 
	{
		flags_old_serialno  = AVP_FLAGS_UNNECESSARY;
	}
	else
	{
		flags_old_serialno = AVP_FLAGS_NECESSARY;
	}
	Avp oldserialno_avp_obj = Avp::from_str(avp_oldserialno, flags_old_serialno, oldserialno);
	result = oldserialno_avp_obj.serialize_to_buffer(service_information_buf + length, sizeof(service_information_buf) - length);
	if (result <= 0)
	{
		cerr << "oldserialno_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	Avp recharge_number_avp_obj = Avp::from_str(avp_recharge_number, AVP_FLAGS_NECESSARY, recharge_number);
	result = recharge_number_avp_obj.serialize_to_buffer(service_information_buf + length, sizeof(service_information_buf) - length);
	if (result <= 0)
	{
		cerr << "recharge_number_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	Avp money_value_avp_obj = Avp::from_int(avp_money_value, AVP_FLAGS_NECESSARY, money_value);
	result = money_value_avp_obj.serialize_to_buffer(service_information_buf + length, sizeof(service_information_buf) - length);
	if (result <= 0)
	{
		cerr << "money_value_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	Avp accounttype_avp_obj = Avp::from_int(avp_accounttype, AVP_FLAGS_UNNECESSARY, accounttype);
	result = accounttype_avp_obj.serialize_to_buffer(service_information_buf + length, sizeof(service_information_buf) - length);
	if (result <= 0)
	{
		cerr << "accounttype_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	Avp recharge_method_avp_obj = Avp::from_str(avp_recharge_method, AVP_FLAGS_UNNECESSARY, recharge_method);
	result = recharge_method_avp_obj.serialize_to_buffer(service_information_buf + length, sizeof(service_information_buf) - length);
	if (result <= 0)
	{
		cerr << "recharge_method_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	//将最底层buffer加入AVP
	Avp airrecharge_information_avp_obj = Avp::from_buf(avp_airrecharge_information, AVP_FLAGS_WITH_VID, service_information_buf, length);
	airrecharge_information_avp_obj.set_avp_vendorid(VENDOR_ID_AIRRECHARGE_INFORMATION);
	//最底层 group endmpelete

	//序列化第二层
	length = 0;
	memset(service_information_buf, 0, sizeof(service_information_buf));
	result = airrecharge_information_avp_obj.serialize_to_buffer(service_information_buf, sizeof(service_information_buf));
	if (result <= 0)
	{
		cerr << "airrecharge_information_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	//序列化 首层
	Avp in_information_avp_obj = Avp::from_buf(avp_in_information, AVP_FLAGS_WITH_VID, service_information_buf, length);
	in_information_avp_obj.set_avp_vendorid(VENDOR_ID_IN_INFORMATION);

	length = 0;
	memset(service_information_buf, 0, sizeof(service_information_buf));
	result = in_information_avp_obj.serialize_to_buffer(service_information_buf, sizeof(service_information_buf));
	if (result <= 0)
	{
		cerr << "airrecharge_information_avp_obj avp serialize failed." << endl;
		return -1;
	}
	length += result;

	//生成顶层AVP
	Avp service_information_avp_obj = Avp::from_buf(avp_service_information, AVP_FLAGS_WITH_VID, service_information_buf, length);
	service_information_avp_obj.set_avp_vendorid(VENDOR_ID_SERVICE_INFORMATION);

	//加入本Diameter
	add_avp(service_information_avp_obj);
	return serialize_to_buffer(out_buffer, buf_length);
}


int CapabilitiesExchangeAnswer::deserialize(const uint8_t* in_buffer, size_t buf_length)
{
	Avp avp;
	int result = parse_from_buffer((uint8_t*)in_buffer, buf_length);
	if (result < 0)
	{
		return -1;
	}
	
	int succ = extract_spec_avp(avp_result_code, avp);
	if (succ != -1)
	{
		size_t i;
		result_code = 0;

		for (i = 0; i < avp.data.size(); i++)
		{
			*((char*)&result_code + i)= avp.data[i];
		}
		result_code = CONVERT_UINT32(result_code);
	}
	else
	{
		cerr << "CANNOT FOUND RESULT CODE." << endl;
	}
	return result;
}


int CapabilitiesExchangeAnswer::serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence)
{
	unused_for_compile(out_buffer);
	unused_for_compile(buf_length);
	unused_for_compile(sequence);

	throw std::logic_error("The method or operation is not implemented.");
}


CreditControlAnswer::CreditControlAnswer() : result_code(0), operation_result(0), balance(0)
{

}


CreditControlAnswer::~CreditControlAnswer()
{

}


int CreditControlAnswer::deserialize(const uint8_t* in_buffer, size_t buf_length)
{
	int length = parse_from_buffer((uint8_t*)in_buffer, buf_length);
	if (length < 0)
	{
		cerr << "parse CCA from buffer error." << endl;
		return -1;
	}

	int result = extract_spec_as_uint32(avp_result_code, result_code);
	if (result < 0)
	{
		cerr << "error , not found result_code: " << avp_result_code << endl;
	}

	result = extract_spec_as_str(avp_session_id, session_id);
	if (result < 0)
	{
		cerr << "error , not found session_id: " << avp_session_id << endl;
	}

	//group begin...
	uint8_t service_buf[1024];
	memset(service_buf, 0, sizeof(service_buf));

	//将 avp_service_information 内容抽出为buffer
	result = extract_spec_as_buf(avp_service_information, service_buf, sizeof(service_buf));
	if (result < 0)
	{
		cerr << "error, avp_service_information not found." << endl;
		return length;
	}

	//在 avp_service_information 的buffer中寻找  IN-Information
	int pos = 0;
	int group_length = result;
	int found = false;
	while (1)
	{
		Avp in_infor_avpobj;
		result = Avp::extract_one_avp(service_buf + pos, group_length - pos, in_infor_avpobj);
		if (result <= 0)
		{
			break;
		}
		if (in_infor_avpobj.code != avp_in_information)
		{
			pos += result;
			continue;
		}
		//找到，抽取内容到buffer
		result = in_infor_avpobj.data_to_buffer(service_buf, sizeof(service_buf));
		if (result <= 0)
		{
			cerr << "error, in_information data buffer error." << endl;
			return length;
		}
		found = true;
		group_length = result;
		break;
	}

	if (!found)
	{
		cerr << "cannot found avp_in_information on Service-Information" << endl;
		return length;
	}

	//继续查找AirRecharge-Infomation
	pos = 0;
	found = false;
	while (1)
	{
		Avp airrecharge_avpobj;
		result = Avp::extract_one_avp(service_buf + pos, group_length - pos, airrecharge_avpobj);
		if (result <= 0)
		{
			break;
		}
		if (airrecharge_avpobj.code != avp_airrecharge_information)
		{
			pos += result;
			continue;
		}
		result = airrecharge_avpobj.data_to_buffer(service_buf, sizeof(service_buf));
		if (result <= 0)
		{
			cerr << "error, airrecharge_information data buffer error." << endl;
			return length;
		}
		found = true;
		group_length = result;
		break;
	}

	if (!found)
	{
		cerr << "cannot found airrecharge_information on in_information" << endl;
		return length;
	}

	map<uint32_t, Avp> inner_avp;
	pos = 0;
	while (true)
	{
		Avp cur_avp;
		result = Avp::extract_one_avp(service_buf + pos, group_length - pos, cur_avp);
		if (result <= 0)
		{
			break;
		}
		inner_avp[cur_avp.code] = cur_avp;
		pos += result;
	}

	if (inner_avp.find(avp_transactionid) != inner_avp.end())
	{
		result = inner_avp[avp_transactionid].data_to_string(transactionid);
		if (result <= 0)
		{
			cerr << "data buffer to string on " << "avp_transactionid" << " error." << endl;
		}
	}

	if (inner_avp.find(avp_trade_time) != inner_avp.end())
	{
		result = inner_avp[avp_trade_time].data_to_string(tradetime);
		if (result <= 0)
		{
			cerr << "data buffer to string on " << "avp_trade_time" << " error." << endl;
		}
	}

	if (inner_avp.find(avp_operation_result) != inner_avp.end())
	{
		result = inner_avp[avp_operation_result].data_to_uint32(operation_result);
		if (result <= 0)
		{
			cerr << "data buffer to string on " << "avp_operation_result" << " error." << endl;
		}
	}

	if (inner_avp.find(avp_accountdate) != inner_avp.end())
	{
		result = inner_avp[avp_accountdate].data_to_string(accountdate);
		if (result <= 0)
		{
			cerr << "data buffer to string on " << "avp_accountdate" << " error." << endl;
		}
	}

	if (inner_avp.find(avp_service_type) != inner_avp.end())
	{
		result = inner_avp[avp_service_type].data_to_string(service_type);
		if (result <= 0)
		{
			cerr << "data buffer to string on " << "avp_service_type" << " error." << endl;
		}
	}

	if (inner_avp.find(avp_accountbalance) != inner_avp.end())
	{
		result = inner_avp[avp_accountbalance].data_to_uint32(balance);
		if (result <= 0)
		{
			cerr << "data buffer to string on " << "avp_accountbalance" << "error." << endl;
		}
	}

	return length;
}


int CreditControlAnswer::serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence)
{
	unused_for_compile(out_buffer);
	unused_for_compile(buf_length);
	unused_for_compile(sequence);
	throw std::logic_error("The method or operation is not implemented.");
}


int DeviceWatchdogAnswer::deserialize(const uint8_t* in_buffer, size_t buf_length)
{
	unused_for_compile(in_buffer);
	unused_for_compile(buf_length);

	throw std::logic_error("The method or operation is not implemented.");
}


int DeviceWatchdogAnswer::serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence)
{
	CHECK_STRING_FIELD_RETURN(origin_host, -1);
	CHECK_STRING_FIELD_RETURN(origin_realm, -1);

	header.version = 1;
	header.code = CODE_DWA;
	header.flags.flag_r = 0;
	header.hop_by_hop = sequence;
	header.end_to_end = sequence;

	add_avp(Avp::from_int(avp_result_code, AVP_FLAGS_NECESSARY, result_code));
	add_avp(Avp::from_str(avp_origin_host, AVP_FLAGS_NECESSARY, origin_host));
	add_avp(Avp::from_str(avp_origin_realm, AVP_FLAGS_NECESSARY, origin_realm));
	add_avp(Avp::from_int(avp_origin_state_id, AVP_FLAGS_NECESSARY, original_state_id));

	return serialize_to_buffer(out_buffer, buf_length);
}
