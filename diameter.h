#ifndef _GUARD_H_DIAMETER_H_
#define _GUARD_H_DIAMETER_H_

#include <stdint.h>
#include <vector>
#include <string>
#include <exception>

//头长度
#define DIAMETER_HEADER_LENGTH 20
//最小AVP长度
#define DIAMETER_AVP_MIN_LENGTH 8
#define DIAMETER_MAX_LENGTH 1<<24

using std::string;
using std::vector;
using std::exception;


#define my_htons(_n)  ((uint16_t)((((_n) & 0xff) << 8) | (((_n) >> 8) & 0xff)))
#define my_ntohs(_n)  ((uint16_t)((((_n) & 0xff) << 8) | (((_n) >> 8) & 0xff)))
#define my_htonl(_n)  ((uint32_t)( (((_n) & 0xff) << 24) | (((_n) & 0xff00) << 8) | (((_n) >> 8)  & 0xff00) | (((_n) >> 24) & 0xff) ))
#define my_ntohl(_n)  ((uint32_t)( (((_n) & 0xff) << 24) | (((_n) & 0xff00) << 8) | (((_n) >> 8)  & 0xff00) | (((_n) >> 24) & 0xff) ))


#ifdef _AIX
#define ENDIAN 1
#else
#define ENDIAN 0
#endif


#if ENDIAN
#define CONVERT_UINT32(_n) (_n)
#define CONVERT_UINT16(_n) (_n)
#else
#define CONVERT_UINT32(_n) my_htonl(_n)
#define CONVERT_UINT16(_n) my_htons(_n)
#endif


#ifdef WIN32
#define SIZE_FMT "d"
#else 
#define SIZE_FMT "zu"
#endif


#define unused_for_compile(x) (void)x


class Avp
{
public:
	uint32_t code;
	union
	{
		struct {
#if ENDIAN
			uint8_t flag_v : 1;
			uint8_t flag_m : 1;
			uint8_t flag_p : 1;
			uint8_t _unused : 5;
#else
			uint8_t _unused : 5;
			uint8_t flag_p : 1;
			uint8_t flag_m : 1;
			uint8_t flag_v : 1;
#endif
		};
		uint8_t flags_value;
	}flags;
	//同应该是24位...
	uint32_t length;
	uint32_t realy_data_length;
	uint32_t vendor_id;
	vector<uint8_t> data;
public:
	Avp() :code(0), length(0), vendor_id(0)
	{
		flags.flags_value = 0;
	};
	~Avp(){};
public:
	void clear();
	//序列化，返回 小于0 失败，返回大于0为序列化后的长度标志，无等于0；
	int serialize_to_buffer(uint8_t* out_buffer, size_t in_length);

	/*
	从一个buffer中拆出一个avp
	返回0，无avp
	返回-1，错误
	返回大于0，即avp用掉的buffer，剩余内容可继续调用此函数；
	out 为输出
	*/
	static int extract_one_avp(uint8_t* in_buffer, size_t in_length, Avp& out);
	int data_to_buffer(uint8_t* in_buffer, size_t in_length);
	int data_to_string(string& out);
	int data_to_uint32(uint32_t& out);
	//dump
	void dump_avp() const;

	//原始方式新增AVP
	void set_avp_info(uint32_t code, uint8_t hasVendorId, uint8_t isNeed, uint8_t isEncrypt);
	void set_avp_vendorid(uint32_t vendor_id);
	void set_avp_data(const uint8_t* buffer, size_t length);

	//特化方式
	void set_str_avp(uint32_t code, uint8_t flags, const string& data);
	void set_int_avp(uint32_t code, uint8_t flags, uint32_t value);
	void set_buf_avp(uint32_t code, uint8_t flags, uint8_t* buffer, size_t length);

	//静态工厂方法
	static Avp from_str(uint32_t code, uint8_t flags, const string& data);
	static Avp from_int(uint32_t code, uint8_t flags, uint32_t value);
	static Avp from_buf(uint32_t code, uint8_t flags, uint8_t* buffer, size_t length);

	//groupd
	void get_grouped(vector<Avp>& out);
};


class DiameterHeader
{
public:
	uint8_t version;
	//应该是24位的
	uint32_t length;
	union
	{
		struct {
#if ENDIAN
			uint8_t flag_r : 1;
			uint8_t flag_p : 1;
			uint8_t flag_e : 1;
			uint8_t flag_t : 1;
			uint8_t _unused : 4;
#else
			uint8_t _unused : 4;
			uint8_t flag_t : 1;
			uint8_t flag_e : 1;
			uint8_t flag_p : 1;
			uint8_t flag_r : 1;
#endif
		};
		uint8_t flags_value;
	}flags;

	uint32_t code;
	uint32_t application_id;
	uint32_t hop_by_hop;
	uint32_t end_to_end;
public:
	DiameterHeader() : version(1), length(0), code(0), application_id(0), hop_by_hop(0), end_to_end(0)
	{
		flags.flags_value = 0;
	};
	~DiameterHeader(){};
public:
	//分析 Diameter 头, 小于0 失败，0为成功，暂无大于0；
	int parse_diameter_header(uint8_t* buffer);
	/*
	序列化到buffer
	返回20，成功, 因为包头长度定长 20 字节；
	非0，失败！
	*/
	int serialize_header_to_buffer(uint8_t* out_buffer, size_t max_length);

	//dump
	void dump_header() const;
};


class Diameter
{
public:
	Diameter(){};
	virtual ~Diameter(){};
public:
	DiameterHeader header;
	vector<Avp> avp_list;
	typedef vector<Avp>::iterator AVPListIter;
	typedef vector<Avp>::const_iterator AVPListConstIter;
public:
	void clear();
	//序列化为buffer
	//返回小于0 失败！，大于0为buffer长度，无等于0；
	int serialize_to_buffer(uint8_t* outbuffer, size_t max_length);

	//反序列化为对象， 小于0 失败，大于0为用掉的字节数
	int parse_from_buffer(uint8_t* inbuffer, size_t in_length);

	//dump
	void dump() const;

	//暂只能增加不能删除
	void add_avp(const Avp& avp) {
		avp_list.push_back(avp);
	}

	//获取指定的AVP, out 输出，返回-1未找到，返回0成功
	int extract_spec_avp(uint32_t avp_code, Avp& out);
	//获取为特化类型, int, 
	int extract_spec_as_uint32(uint32_t avp_code, uint32_t& out);
	//获取为string
	int extract_spec_as_str(uint32_t avp_code, string& out);
	//获取为buffer
	int extract_spec_as_buf(uint32_t avp_code, uint8_t* outbuffer, size_t outlength);
};


#endif

