#ifndef _GUARD_H_DCC_FRAME_H_
#define _GUARD_H_DCC_FRAME_H_

#include "diameter.h"
#include <stdexcept>

#define T_CAPABILITIESEXCHANGE 257
#define T_CREDITCONTROL 272
#define T_DEVICEWATCHDOG 280
#define T_DISCONNECTPEER 282


#define CODE_CER T_CAPABILITIESEXCHANGE
#define CODE_CEA T_CAPABILITIESEXCHANGE
#define CODE_DWR T_DEVICEWATCHDOG
#define CODE_DWA T_DEVICEWATCHDOG
#define CODE_DPR T_DISCONNECTPEER
#define CODE_DPA T_DISCONNECTPEER
#define CODE_CCR T_CREDITCONTROL
#define CODE_CCA T_CREDITCONTROL


#define DIAMETER_FLAGS_CER 0x80
#define DIAMETER_FLAGS_CEA 0x00
#define DIAMETER_FLAGS_DWR 0x80
#define DIAMETER_FLAGS_DWA 0x00
#define DIAMETER_FLAGS_CCR 0xC0
#define DIAMETER_FLAGS_CCA 0x40
#define DIAMETER_FLAGS_DPR 0x80
#define DIAMETER_FLAGS_DPA 0x00


#define APPLICATION_ID 0x00


//CER
#define avp_origin_host 264
#define avp_origin_realm 296
#define avp_host_ip_address 257
#define avp_vendor_id 266
#define avp_product_name 269
#define avp_origin_state_id 278
#define avp_supported_vendor_id 265
#define avp_auth_application_id 258
#define avp_acct_application_id 259
#define avp_inband_security_id 299
#define avp_firmware_revision 267


//CEA
#define avp_result_code 268


//CCR
#define avp_session_id 263
//#define avp_origin_host 264
#define avp_destination_host 293
#define avp_destination_realm 283
//#define avp_auth_application_id 258
#define avp_service_context_id 461
#define avp_cc_request_type 416
#define avp_cc_request_number 415
#define avp_event_timestamp 55
#define avp_subscription_id 443
#define avp_subscription_id_type 450
#define avp_subscription_id_data 444
#define avp_requested_action 436
#define avp_service_identifier 439
#define avp_service_information 873
#define avp_in_information 20300
#define avp_airrecharge_information 20760
#define avp_service_type 20761
#define avp_transactionid 20762
#define avp_trade_time 20659
#define avp_serialno 20763
#define avp_oldserialno 20764
#define avp_recharge_number 20765
#define avp_money_value 20766
#define avp_accounttype 20652
#define avp_recharge_method 20767

//CCA
//#define avp_session_id 263
//#define avp_result_code 268
//#define avp_origin_host 264
//#define avp_origin_realm 296
//#define avp_auth_application_id 258
//#define avp_cc_request_type 416
//#define avp_cc_request_number 415
//#define avp_event_timestamp 55
#define avp_credit_control_failure_handling 427
//#define avp_service_information 873
//#define avp_airrecharge_information 20760
// #define avp_service_type 20761
// #define avp_transactionid 20762
// #define avp_trade_time 20659
#define avp_operation_result 20768
#define avp_accountdate 20769
#define avp_accountbalance 20770


//DPR
#define avp_disconnect_cause 273


//FLAGS 似乎只有如下三种取值
#define AVP_FLAGS_40 0x40
#define AVP_FLAGS_00 0x00
#define AVP_FLAGS_80 0x80

#define AVP_FLAGS_NECESSARY AVP_FLAGS_40
#define AVP_FLAGS_UNNECESSARY AVP_FLAGS_00
#define AVP_FLAGS_WITH_VID 0xC0


#define VENDOR_ID_AIRRECHARGE_INFORMATION 0x013C68
#define VENDOR_ID_IN_INFORMATION 0x013C68
#define VENDOR_ID_SERVICE_INFORMATION 0x28AF


#define CHECK_STRING_FIELD_RETURN(fieldname, retvalue)	\
	do {	\
		if((this)->fieldname.empty()) return retvalue;	\
			} while(0);


class DccFrame : public Diameter
{
public:
	DccFrame() : sequence(0) {}
	virtual ~DccFrame() {}

public:
	virtual int deserialize(const uint8_t* in_buffer, size_t buf_length) = 0;
	virtual int serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence) = 0;
	string origin_host;
	string origin_realm;
	uint32_t sequence;
};


class CapabilitiesExchangeRequest : public DccFrame
{
public:
	CapabilitiesExchangeRequest() : vendor_id(0), origin_state_id(0), supported_vendor_id(0), auth_application_id(0), 
		acct_application_id(0), inband_security_id(0), firmware_revision(0) {}
	~CapabilitiesExchangeRequest(){}
public:
	virtual int deserialize(const uint8_t* in_buffer, size_t buf_length);

	virtual int serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence);
	string host_ip_address;
	string product_name;
	uint32_t vendor_id;
	uint32_t origin_state_id;
	uint32_t supported_vendor_id;
	uint32_t auth_application_id;
	uint32_t acct_application_id;
	uint32_t inband_security_id;
	uint32_t firmware_revision;
};


class CapabilitiesExchangeAnswer : public DccFrame
{
public:
	CapabilitiesExchangeAnswer() : result_code(0) {}
	~CapabilitiesExchangeAnswer(){}
public:
	virtual int deserialize(const uint8_t* in_buffer, size_t buf_length);
	virtual int serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence);
	uint32_t result_code;
};


class CreditControlRequest : public DccFrame
{
public:
	CreditControlRequest() :timestamp(0), auth_application_id(0), 
		cc_request_type(0), cc_request_number(0), event_timestamp(0), subscription_id_type(0),
		requested_action(0), service_identifier(0), money_value(0), accounttype(0) {};
	~CreditControlRequest(){};
	virtual int deserialize(const uint8_t* in_buffer, size_t buf_length);
	virtual int serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence);

	uint32_t timestamp;
	string session_id;
	string destination_host;
	string destination_realm;
	uint32_t auth_application_id;
	string service_context_id;
	uint32_t cc_request_type;
	uint32_t cc_request_number;
	uint32_t event_timestamp;

	//group begin
	uint32_t subscription_id_type;
	//手机号码
	string subscription_id_data;
	//group end

	uint32_t requested_action;
	uint32_t service_identifier;
	
	//group begin
	string service_type;
	string transactionid;
	string trade_time;
	string serialno;
	//empty
	string oldserialno;
	string recharge_number;
	uint32_t money_value;
	uint32_t accounttype;
	string recharge_method;
};


class CreditControlAnswer : public DccFrame
{
public:
	CreditControlAnswer();
	~CreditControlAnswer();

public:
	virtual int deserialize(const uint8_t* in_buffer, size_t buf_length);
	virtual int serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence);

	uint32_t result_code;
	string service_type;
	string session_id;
	string transactionid;
	string tradetime;
	uint32_t operation_result;
	string accountdate;
	uint32_t balance;
};


class DeviceWatchdogRequest : public DccFrame
{
public:
	virtual int deserialize(const uint8_t* in_buffer, size_t buf_length);
	virtual int serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence);
};


class DeviceWatchdogAnswer : public DccFrame
{
public:
	DeviceWatchdogAnswer() : result_code(0), original_state_id(0) {}
	~DeviceWatchdogAnswer() {}

	uint32_t result_code;
	uint32_t original_state_id;

	virtual int deserialize(const uint8_t* in_buffer, size_t buf_length);

	virtual int serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence);

};


class DisconnectPeerRequest : public DccFrame
{
public:
	DisconnectPeerRequest() :DccFrame(), disconnect_cause(2) {};
	~DisconnectPeerRequest(){};

	virtual int deserialize(const uint8_t* in_buffer, size_t buf_length);
	virtual int serialize(uint8_t* out_buffer, size_t buf_length, uint32_t sequence);

	uint32_t disconnect_cause;
};


class DisconnectPeerAnswer : public DccFrame
{
	//
};


#endif