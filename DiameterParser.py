#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals
from __future__ import print_function

import struct
import socket
import time
import datetime


DIAMETER_HEADER_LENGTH = 20
DIAMETER_AVP_MIN_LENGTH = 8
DIAMETER_MAX_LENGTH = 1 << 24
# struct format, unsigned int32_t
UI32FMT = b'!I'
# for uint16_t
UI16FMT = b'!H'
# default encoding.
ENCODE = 'UTF-8'


class CONST:
    T_CAPABILITIESEXCHANGE = 257
    T_CREDITCONTROL = 272
    T_DEVICEWATCHDOG = 280
    T_DISCONNECTPEER = 282

    CODE_CER = T_CAPABILITIESEXCHANGE
    CODE_CEA = T_CAPABILITIESEXCHANGE
    CODE_DWR = T_DEVICEWATCHDOG
    CODE_DWA = T_DEVICEWATCHDOG
    CODE_DPR = T_DISCONNECTPEER
    CODE_DPA = T_DISCONNECTPEER
    CODE_CCR = T_CREDITCONTROL
    CODE_CCA = T_CREDITCONTROL

    DIAMETER_FLAGS_CER = 0x80
    DIAMETER_FLAGS_CEA = 0x00
    DIAMETER_FLAGS_DWR = 0x80
    DIAMETER_FLAGS_DWA = 0x00
    DIAMETER_FLAGS_CCR = 0xC0
    DIAMETER_FLAGS_CCA = 0x40
    DIAMETER_FLAGS_DPR = 0x80
    DIAMETER_FLAGS_DPA = 0x00

    APPLICATION_ID = 0x00

    avp_origin_host = 264
    avp_origin_realm = 296
    avp_host_ip_address = 257
    avp_vendor_id = 266
    avp_product_name = 269
    avp_origin_state_id = 278
    avp_supported_vendor_id = 265
    avp_auth_application_id = 258
    avp_acct_application_id = 259
    avp_inband_security_id = 299
    avp_firmware_revision = 267

    avp_result_code = 268

    avp_session_id = 263
    avp_destination_host = 293
    avp_destination_realm = 283
    avp_service_context_id = 461
    avp_cc_request_type = 416
    avp_cc_request_number = 415
    avp_event_timestamp = 55
    avp_subscription_id = 443
    avp_subscription_id_type = 450
    avp_subscription_id_data = 444
    avp_requested_action = 436
    avp_service_identifier = 439
    avp_service_information = 873
    avp_in_information = 20300
    avp_airrecharge_information = 20760
    avp_service_type = 20761
    avp_transactionid = 20762
    avp_trade_time = 20659
    avp_serialno = 20763
    avp_oldserialno = 20764
    avp_recharge_number = 20765
    avp_money_value = 20766
    avp_accounttype = 20652
    avp_recharge_method = 20767

    avp_credit_control_failure_handling = 427
    avp_operation_result = 20768
    avp_accountdate = 20769
    avp_account_balance = 20770

    avp_disconnect_cause = 273

    AVP_FLAGS_40 = 0x40
    AVP_FLAGS_00 = 0x00
    AVP_FLAGS_80 = 0x80

    AVP_FLAGS_NECESSARY = AVP_FLAGS_40
    AVP_FLAGS_UNNECESSARY = AVP_FLAGS_00
    AVP_FLAGS_WITH_VID = 0xC0

    VENDOR_ID_AIRRECHARGE_INFORMATION = 0x013C68
    VENDOR_ID_IN_INFORMATION = 0x013C68
    VENDOR_ID_SERVICE_INFORMATION = 0x28AF

    # global dcc value
    DCC_Service_Centext_Id = "manager@huawei.com"
    DCC_Vendor_Id = 11
    DCC_Product_Name = "ACCT"
    DCC_Host_IP_Address_Type = 1
    DCC_Host_IP_Address_Value = "10.244.152.51"
    DCC_Supported_Vendor_Id = 11
    DCC_Auth_Application_Id = 20
    DCC_Acct_Application_Id = 33
    DCC_Inband_Security_Id = 0
    DCC_Firmware_Revision = 100

    SECONDS_FROM_1900_TO_1970 = 2208988800


class DiameterException(Exception):
    pass


class Avp(object):
    def __init__(self):
        self.code = 0
        self.flag_v = 0
        self.flag_m = 0
        self.flag_p = 0
        self.length = 0
        self.vendor_id = 0
        self.data = bytearray()

    def __str__(self):
        return 'Avp [%d]' % self.code

    def serialize_avp(self):
        buf = bytearray()
        # avp code
        buf += struct.pack(UI32FMT, self.code)
        # length
        pack_length = len(self.data) + 8
        if self.flag_v:
            pack_length += 4
        buf += struct.pack(UI32FMT, pack_length)
        # flags value
        flags = 0
        if self.flag_v:
            flags |= 0x80
        if self.flag_m:
            flags |= 0x40
        if self.flag_p:
            flags |= 0x20
        buf[4] = flags
        # vendor id
        if self.flag_v:
            buf += struct.pack(UI32FMT, self.vendor_id)
        buf.extend(self.data)
        if len(self.data) % 4:
            padding = 4 - len(self.data) % 4
            buf.extend(b'\x00' * padding)
        return buf

    @classmethod
    def extract_one(cls, buf):
        assert len(buf) >= DIAMETER_AVP_MIN_LENGTH, 'too small data for avp'
        avp = Avp()
        pos = 0
        # avp code
        avp.code, = struct.unpack(UI32FMT, buf[:4])
        pos += 4
        # flags
        avp.set_avp_flags(buf[4])
        pos += 1
        # length
        avp.length, = struct.unpack(UI32FMT, b'\x00' + buf[pos: pos + 3])
        pos += 3
        # 长度判断
        frame_length = avp.length
        if avp.length % 4:
            frame_length += 4 - avp.length % 4
        if len(buf) < frame_length:
            return False, None, None
        # if vendor id
        if avp.flag_v:
            avp.vendor_id, = struct.unpack(UI32FMT, buf[pos: pos + 4])
            pos += 4
        avp.data = buf[pos: avp.length]
        return True, buf[frame_length:], avp

    def paded_data(self, data):
        if len(data) % 4:
            padding = 4 - len(data) % 4
            self.data.extend(b'\x00' * padding)
        return data

    def set_avp_data(self, databuf):
        assert len(self.data) == 0, 'duplicate avp data write'
        assert len(databuf) < DIAMETER_MAX_LENGTH, 'too big data for avp.'
        self.data.extend(databuf)

    def set_avp_vendorid(self, vendorid):
        self.vendor_id = vendorid

    def set_avp_flags(self, flags):
        assert flags < 0xFF, 'flags value over 0xFF'
        self.flag_v = (flags & 0x80) >> 7
        self.flag_m = (flags & 0x40) >> 6
        self.flag_p = (flags & 0x20) >> 5

    def set_buf_avp(self, code, flags, buf):
        assert not isinstance(buf, unicode), 'avp buffer not accept unicode'
        self.code = code
        self.set_avp_flags(flags)
        self.set_avp_data(buf)

    def set_int_avp(self, code, flags, value):
        self.code = code
        self.set_avp_flags(flags)
        self.set_avp_data(struct.pack(UI32FMT, value))

    @staticmethod
    def from_buf(code, flags, buf):
        if isinstance(buf, unicode):
            byte_buf = buf.encode(ENCODE)
        else:
            byte_buf = buf
        avp = Avp()
        avp.set_buf_avp(code, flags, byte_buf)
        return avp

    @staticmethod
    def from_uint32(code, flags, value):
        avp = Avp()
        avp.set_int_avp(code, flags, value)
        return avp

    @staticmethod
    def from_grouped(code, flags, avps):
        buf = bytearray()
        avp = Avp()
        for avp_item in avps:
            buf.extend(avp_item.serialize_avp())
        avp.set_buf_avp(code, flags, buf)
        return avp

    def data_as_uint32(self):
        assert len(self.data) == 4, 'size_t of uint32 must be set 4'
        val, = struct.unpack(UI32FMT, self.data)
        return val

    def hex_dump(self, buf):
        out = ''
        for word in buf:
            out += '%02X ' % word
        return out

    def dump(self):
        print('=====================================')
        print("%-18s%d" % ("code", self.code))
        print("%-18s%d" % ("length", self.length))
        print("%-18s%d" % ("V", 1 if self.flag_v else 0))
        print("%-18s%d" % ("M", 1 if self.flag_m else 0))
        print("%-18s%d" % ("P", 1 if self.flag_p else 0))
        if self.flag_v:
            print("%-18s%d\n" % ("vendorId", self.vendor_id))
        print("%-18s%s" % ("data", repr(self.data)))
        print('=====================================')

    @staticmethod
    def parse_grouped_avp(avp):
        '''
        :type avp: Avp
        :param avp: Avp object contain list of avps.
        '''
        avps_buf = avp.data
        avps = []
        while avps_buf:
            flag, avps_buf, cur_avp = Avp.extract_one(avps_buf)
            if not flag:
                break
            avps.append(cur_avp)
        if avps_buf:
            raise DiameterException('buffer left.')
        return avps


class DiameterHeader(object):
    def __init__(self):
        self.version = 0
        self.length = 0
        self.flag_r = 0
        self.flag_p = 0
        self.flag_e = 0
        self.flag_t = 0
        self.cmdcode = 0
        self.application_id = 0
        self.hop_by_hop = 0
        self.end_to_end = 0

    def __str__(self):
        return "Header %d" % self.cmdcode

    def get_flags_val(self):
        flags = 0
        if self.flag_r:
            flags |= 0x80
        if self.flag_p:
            flags |= 0x40
        if self.flag_e:
            flags |= 0x20
        if self.flag_t:
            flags |= 0x10
        return flags

    def serialize_header(self):
        buf = bytearray()
        # version
        buf += chr(1)
        # length,
        buf += b'\x00' * 3
        # cmd code
        buf += struct.pack(UI32FMT, self.cmdcode)
        # flags
        buf[4] = self.get_flags_val()
        # appid
        buf += struct.pack(UI32FMT, self.application_id)
        # hop by hop
        buf += struct.pack(UI32FMT, self.hop_by_hop)
        # end to end
        buf += struct.pack(UI32FMT, self.end_to_end)
        assert len(buf) == 20, 'Diameter serialize length error.'
        return buf

    def deserialize_header(self, buf):
        assert len(buf) == 20, 'Diameter header length error.'
        pos = 0
        # version
        self.version = buf[0]
        if self.version != 1:
            raise DiameterException('Diameter header version error.')
        pos += 1
        # length
        self.length, = struct.unpack(UI32FMT, b'\x00' + buf[pos: pos + 3])
        pos += 3
        # flags
        flags = buf[pos]
        self.flag_r = (0x80 & flags) >> 7
        self.flag_p = (0x40 & flags) >> 6
        self.flag_e = (0x20 & flags) >> 5
        self.flag_t = (0x10 & flags) >> 4
        pos += 1
        # cmd code
        self.cmdcode, = struct.unpack(UI32FMT, b'\x00' + buf[pos: pos + 3])
        pos += 3
        # application id
        self.application_id, = struct.unpack(UI32FMT, buf[pos: pos + 4])
        pos += 4
        # hop_by_hop
        self.hop_by_hop, = struct.unpack(UI32FMT, buf[pos: pos + 4])
        pos += 4
        # end by end
        self.end_to_end, = struct.unpack(UI32FMT, buf[pos: pos + 4])

    def dump(self):
        print('=====================================')
        print("%-18s%d" % ("version", self.version))
        print("%-18s%d" % ("length", self.length))
        print("%-18s%d" % ("R", 1 if self.flag_r else 0))
        print("%-18s%d" % ("P", 1 if self.flag_p else 0))
        print("%-18s%d" % ("E", 1 if self.flag_e else 0))
        print("%-18s%d" % ("T", 1 if self.flag_t else 0))
        print("%-18s%d" % ("code", self.cmdcode))
        print("%-18s%d" % ("app_id", self.application_id))
        print("%-18s%d" % ("hop-by-hop", self.hop_by_hop))
        print("%-18s%d" % ("end-to-end", self.end_to_end))
        print('=====================================')


class Diameter(object):
    def __init__(self):
        self.header = DiameterHeader()
        ': :type self.avps: list[Avp]'
        self.avps = []

    def __str__(self):
        return "Diameter %d" % self.header.cmdcode

    def serialize_to_buffer(self):
        assert self.avps, 'Empty AVP on diameter object'
        buf = self.header.serialize_header()
        assert len(buf) == DIAMETER_HEADER_LENGTH, 'header len err'
        for avp in self.avps:
            buf.extend(avp.serialize_avp())
        # fix header length
        len_buf3 = struct.pack(UI32FMT, len(buf))
        buf[1] = len_buf3[1]
        buf[2] = len_buf3[2]
        buf[3] = len_buf3[3]
        return buf

    def deserialize_from_buffer(self, buf):
        assert not self.avps, 'dup deserialize on diameter object?'
        self.header.deserialize_header(buf[: DIAMETER_HEADER_LENGTH])
        avps_buf = buf[DIAMETER_HEADER_LENGTH:]
        while avps_buf:
            flag, avps_buf, avp = Avp.extract_one(avps_buf)
            if not flag:
                break
            self.add_avp(avp)
        # if left data, deserialize failed.
        if avps_buf:
            return False
        return True

    def dump(self):
        self.header.dump()
        for avp in self.avps:
            avp.dump()

    def add_avp(self, avp):
        self.avps.append(avp)

    def add_grouped_avp(self, code, flags, avps):
        '''
        :type avps: list[Avp]
        '''
        self.avps.append(Avp.from_grouped(code, flags, avps))

    def avp_at(self, code):
        '''
        :type code: str
        :param code: avp code
        '''
        for avp in self.avps:
            ': :type avp: Avp'
            if avp.code == code:
                return avp
        return None

    @staticmethod
    def show_byte(sIn):
        for pos, word in enumerate(sIn):
            if pos and pos % 16 == 0:
                print('\n%02X ' % ord(word), end='')
            else:
                print('%02X ' % ord(word), end='')


class DccFrame(Diameter):
    def __init__(self):
        Diameter.__init__(self)
        self.origin_host = ''
        self.origin_realm = ''
        self.sequence = 0
        self.cmdcode = 0

    def extract_field(self):
        raise NotImplementedError()

    def clone(self, diameter):
        self.header = diameter.header
        self.avps = diameter.avps

    def set_avps(self):
        pass

    def add_origin_info(self):
        assert self.origin_host and self.origin_realm, 'origin info empty'
        self.add_avp(Avp.from_buf(CONST.avp_origin_host,
                                  CONST.AVP_FLAGS_NECESSARY,
                                  self.origin_host))
        self.add_avp(Avp.from_buf(CONST.avp_origin_realm,
                                  CONST.AVP_FLAGS_NECESSARY,
                                  self.origin_realm))

    def serialize(self, sequence):
        if (not self.origin_host) or (not self.origin_realm):
            return None
        self.header.version = 1
        self.header.hop_by_hop = sequence
        self.header.end_to_end = sequence
        self.header.cmdcode = self.cmdcode
        self.set_avps()
        buf = self.serialize_to_buffer()
        return str(buf)

    def _deserialize(self, buf):
        pass


class DisconnectPeerRequest(DccFrame):
    def __init__(self):
        DccFrame.__init__(self)
        self.cmdcode = CONST.CODE_DPR
        self.disconnect_cause = 0

    def __str__(self):
        return "Diameter DPR at 0x%s" % hex(id(self))

    def set_avps(self):
        self.add_origin_info()
        self.add_avp(Avp.from_uint32(CONST.avp_disconnect_cause,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.disconnect_cause))


class DisconnectPeerAnswer(DccFrame):
    def __init__(self):
        DccFrame.__init__(self)
        self.cmdcode = CONST.CODE_DPA

    def __str__(self):
        return "Diameter DPA at 0x%s" % hex(id(self))


class DeviceWatchdogRequest(DccFrame):
    def __init__(self):
        DccFrame.__init__(self)
        self.cmdcode = CONST.CODE_DWR

    def __str__(self):
        return "Diameter DWR at 0x%s" % hex(id(self))

    def set_avps(self):
        self.header.version = 1
        self.header.cmdcode = CONST.CODE_DWR
        self.header.flag_r = 1
        self.add_origin_info()

    def extract_field(self):
        '''do nothing, finished.'''
        pass


class DeviceWatchdogAnswer(DccFrame):
    def __init__(self):
        DccFrame.__init__(self)
        self.cmdcode = CONST.CODE_DWA
        self.result_code = 0

    def __str__(self):
        return "Diameter DWA at 0x%s" % hex(id(self))

    def set_avps(self):
        self.add_origin_info()
        self.add_avp(Avp.from_uint32(CONST.avp_result_code,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.result_code))

    def extract_field(self):
        avp_resultcode = self.avp_at(CONST.avp_result_code)
        if not avp_resultcode:
            self.result_code = avp_resultcode.data_as_uint32()


class CreditControlAnswer(DccFrame):
    def __init__(self):
        DccFrame.__init__(self)
        self.cmdcode = CONST.CODE_CCA
        self.result_code = 0
        self.operation_result = 0
        self.accountdate = ''
        self.balance = 0
        self.transactionid = ''
        self.trade_time = ''
        self.service_type = ''

    def __str__(self):
        return "Diameter CCA at 0x%s" % hex(id(self))

    def extract_field(self):
        result_code_avp = self.avp_at(CONST.avp_result_code)
        if result_code_avp:
            self.result_code = result_code_avp.data_as_uint32()
        avp_873 = self.avp_at(CONST.avp_service_information)
        if not avp_873:
            return
        avp_20300_s = Avp.parse_grouped_avp(avp_873)
        if not avp_20300_s:
            return
        avp_20760_s = Avp.parse_grouped_avp(avp_20300_s[0])
        if not avp_20760_s:
            return
        avp_airrecharge_infos = Avp.parse_grouped_avp(avp_20760_s[0])
        for avp in avp_airrecharge_infos:
            code = avp.code
            if code == CONST.avp_operation_result:
                self.operation_result = avp.data_as_uint32()
            elif code == CONST.avp_accountdate:
                self.accountdate = str(avp.data).strip('\x00')
            elif code == CONST.avp_account_balance:
                self.balance = avp.data_as_uint32()
            elif code == CONST.avp_transactionid:
                self.transactionid = str(avp.data).strip('\x00')
            elif code == CONST.avp_trade_time:
                self.trade_time = str(avp.data).strip('\x00')
            elif code == CONST.avp_service_type:
                self.service_type = str(avp.data).strip('\x00')


class CreditControlRequest(DccFrame):
    def __init__(self):
        DccFrame.__init__(self)
        self.cmdcode = CONST.CODE_CCR
        self.timestamp = 0
        self.session_id = ''
        self.destination_host = ''
        self.destination_realm = ''
        self.auth_application_id = 0
        self.service_context_id = 0
        self.cc_request_type = 0
        self.cc_request_number = 0
        self.event_timestamp = 0
        # group 1 begin
        self.subscription_id_type = 0
        self.subscription_id_data = ''
        # group 1 end
        self.request_action = 0
        self.service_identifier = 0
        # group 2 begin
        self.service_type = ''
        self.transactionid = ''
        self.trade_time = ''
        self.serialno = ''
        self.oldserialno = ''
        self.recharge_number = ''
        self.money_value = 0
        self.accounttype = 0
        self.recharge_method = ''

    def __str__(self):
        return "Diameter CCR at 0x%s" % hex(id(self))

    def set_avps(self):
        self.header.version = 1
        self.header.application_id = 4
        self.header.cmdcode = CONST.CODE_CCR
        self.header.flag_r = 1
        self.header.flag_p = 1
        self.cc_request_type = 4
        self.service_identifier = 7
        timestamp_since_1900 = self.timestamp + CONST.SECONDS_FROM_1900_TO_1970
        self.event_timestamp = timestamp_since_1900
        sessionid = (self.origin_host +
                     ';%d' % self.event_timestamp +
                     ';%d' % self.header.hop_by_hop)
        self.add_avp(Avp.from_buf(CONST.avp_session_id,
                                  CONST.AVP_FLAGS_NECESSARY,
                                  sessionid))
        self.add_origin_info()
        self.add_avp(Avp.from_buf(CONST.avp_destination_host,
                                  CONST.AVP_FLAGS_NECESSARY,
                                  self.destination_host))
        self.add_avp(Avp.from_buf(CONST.avp_destination_realm,
                                  CONST.AVP_FLAGS_NECESSARY,
                                  self.destination_realm))
        self.add_avp(Avp.from_uint32(CONST.avp_auth_application_id,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.auth_application_id))
        self.add_avp(Avp.from_buf(CONST.avp_service_context_id,
                                  CONST.AVP_FLAGS_NECESSARY,
                                  self.service_context_id))
        self.add_avp(Avp.from_uint32(CONST.avp_cc_request_type,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.cc_request_type))
        self.add_avp(Avp.from_uint32(CONST.avp_cc_request_number,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.cc_request_number))
        self.add_avp(Avp.from_uint32(CONST.avp_event_timestamp,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.event_timestamp))
        # grouped subscription id begin
        # asia not asia, avps_subscription_id_avps
        asia = []
        asia.append(Avp.from_uint32(CONST.avp_subscription_id_type,
                                    CONST.AVP_FLAGS_NECESSARY,
                                    self.subscription_id_type))
        asia.append(Avp.from_buf(CONST.avp_subscription_id_data,
                                 CONST.AVP_FLAGS_NECESSARY,
                                 self.subscription_id_data))
        self.add_grouped_avp(CONST.avp_subscription_id,
                             CONST.AVP_FLAGS_NECESSARY,
                             asia)
        # grouped subscription id end
        self.add_avp(Avp.from_uint32(CONST.avp_requested_action,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.request_action))
        self.add_avp(Avp.from_uint32(CONST.avp_service_identifier,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.service_identifier))
        # group service information begin
        # what's aia??? airrecharge_information_avps
        aia = []
        aia.append(Avp.from_buf(CONST.avp_service_type,
                                CONST.AVP_FLAGS_NECESSARY,
                                self.service_type))
        aia.append(Avp.from_buf(CONST.avp_transactionid,
                                CONST.AVP_FLAGS_UNNECESSARY,
                                self.transactionid))
        aia.append(Avp.from_buf(CONST.avp_trade_time,
                                CONST.AVP_FLAGS_NECESSARY,
                                self.trade_time))
        aia.append(Avp.from_buf(CONST.avp_serialno,
                                CONST.AVP_FLAGS_NECESSARY,
                                self.serialno))
        if self.oldserialno:
            aia.append(Avp.from_buf(CONST.avp_oldserialno,
                                    CONST.AVP_FLAGS_NECESSARY,
                                    self.oldserialno))
        else:
            aia.append(Avp.from_buf(CONST.avp_oldserialno,
                                    CONST.AVP_FLAGS_UNNECESSARY,
                                    self.oldserialno))
        aia.append(Avp.from_buf(CONST.avp_recharge_number,
                                CONST.AVP_FLAGS_NECESSARY,
                                self.recharge_number))
        aia.append(Avp.from_uint32(CONST.avp_money_value,
                                   CONST.AVP_FLAGS_NECESSARY,
                                   self.money_value))
        aia.append(Avp.from_uint32(CONST.avp_accounttype,
                                   CONST.AVP_FLAGS_UNNECESSARY,
                                   self.accounttype))
        aia.append(Avp.from_buf(CONST.avp_recharge_method,
                                CONST.AVP_FLAGS_UNNECESSARY,
                                self.recharge_method))
        avp_20760 = Avp.from_grouped(CONST.avp_airrecharge_information,
                                     CONST.AVP_FLAGS_WITH_VID, aia)
        avp_20760.set_avp_vendorid(CONST.VENDOR_ID_AIRRECHARGE_INFORMATION)
        # only you!
        in_information_avps = [avp_20760, ]
        avp_20300 = Avp.from_grouped(CONST.avp_in_information,
                                     CONST.AVP_FLAGS_WITH_VID,
                                     in_information_avps)
        avp_20300.set_avp_vendorid(CONST.VENDOR_ID_IN_INFORMATION)
        # Only YOU!
        service_information_avps = [avp_20300, ]
        avp_873 = Avp.from_grouped(CONST.avp_service_information,
                                   CONST.AVP_FLAGS_WITH_VID,
                                   service_information_avps)
        avp_873.set_avp_vendorid(CONST.VENDOR_ID_SERVICE_INFORMATION)
        self.add_avp(avp_873)


class CapabilitiesExchangeRequest(DccFrame):
    def __init__(self):
        DccFrame.__init__(self)
        self.cmdcode = CONST.CODE_CER
        self.host_ip_address = ''
        self.product_name = ''
        self.vendor_id = 0
        self.origin_state_id = 0
        self.supported_vendor_id = 0
        self.auth_application_id = 0
        self.acct_application_id = 0
        self.inband_security_id = 0
        self.firmware_revision = 0

    def __str__(self):
        return "Diameter CER at 0x%s" % hex(id(self))

    def set_avps(self):
        self.header.version = 1
        self.header.cmdcode = CONST.CODE_CER
        self.header.flag_r = 1
        self.add_origin_info()
        # avp_host_ip_address, protocol + aton
        buf = struct.pack(UI16FMT, 1) + socket.inet_aton(self.host_ip_address)
        self.add_avp(Avp.from_buf(CONST.avp_host_ip_address,
                                  CONST.AVP_FLAGS_NECESSARY, buf))
        self.add_avp(Avp.from_uint32(CONST.avp_vendor_id,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.vendor_id))
        if self.product_name:
            self.add_avp(Avp.from_buf(CONST.avp_product_name,
                                      CONST.AVP_FLAGS_UNNECESSARY,
                                      self.product_name))
        self.add_avp(Avp.from_uint32(CONST.avp_origin_state_id,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.origin_state_id))
        self.add_avp(Avp.from_uint32(CONST.avp_supported_vendor_id,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.supported_vendor_id))
        self.add_avp(Avp.from_uint32(CONST.avp_auth_application_id,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.auth_application_id))
        self.add_avp(Avp.from_uint32(CONST.avp_acct_application_id,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.acct_application_id))
        self.add_avp(Avp.from_uint32(CONST.avp_inband_security_id,
                                     CONST.AVP_FLAGS_NECESSARY,
                                     self.inband_security_id))
        self.add_avp(Avp.from_uint32(CONST.avp_firmware_revision,
                                     CONST.AVP_FLAGS_UNNECESSARY,
                                     self.firmware_revision))


class CapabilitiesExchangeAnswer(DccFrame):
    def __init__(self):
        DccFrame.__init__(self)
        self.cmdcode = CONST.CODE_CEA
        self.result_code = 0

    def __str__(self):
        return "Diameter CEA at 0x%s" % hex(id(self))

    def extract_field(self):
        ': :type avp: Avp'
        for avp in self.avps:
            if avp.code == CONST.avp_result_code:
                self.result_code = avp.data_as_uint32()


def test_1():
    b1 = bytearray([0x01, 0x00, 0x00, 0xA8, 0x80, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAD, 0xBA, 0x00, 0x01, 0xAD, 0xBA, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x15, 0x75, 0x70, 0x63, 0x69, 0x2E, 0x67, 0x6D, 0x63, 0x63, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x10, 0x67, 0x6D, 0x63, 0x63, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x01, 0x40, 0x00, 0x00, 0x0E, 0x00, 0x01, 0x31, 0x39, 0x32, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0D, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x16, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x09, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2B, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0B, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00])
    b2 = bytearray([0x01, 0x00, 0x01, 0x48, 0xC0, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0xAD, 0xBA, 0x00, 0x01, 0xAD, 0xBA, 0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x15, 0x75, 0x70, 0x63, 0x69, 0x2E, 0x67, 0x6D, 0x63, 0x63, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x10, 0x67, 0x6D, 0x63, 0x63, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x25, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x1B, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x02, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0xCD, 0x40, 0x00, 0x00, 0x17, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x40, 0x67, 0x6D, 0x63, 0x63, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x00, 0x01, 0xA0, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x9F, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xBB, 0x40, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x01, 0xC2, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xBC, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0xB4, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xB7, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x03, 0x69, 0xC0, 0x00, 0x00, 0x78, 0x00, 0x00, 0x28, 0xAF, 0x00, 0x00, 0x4F, 0x4C, 0xC0, 0x00, 0x00, 0x6C, 0x00, 0x01, 0x3C, 0x68, 0x00, 0x00, 0x51, 0x18, 0xC0, 0x00, 0x00, 0x60, 0x00, 0x01, 0x3C, 0x68, 0x00, 0x00, 0x51, 0x19, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x51, 0x1A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x50, 0xB3, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x51, 0x1B, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x51, 0x1C, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x51, 0x1D, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x51, 0x1E, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0xAC, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x51, 0x1F, 0x00, 0x00, 0x00, 0x0A, 0x30, 0x34, 0x00, 0x00])
    b3 = bytearray([0x01, 0x00, 0x00, 0x3C, 0x80, 0x00, 0x01, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0x00, 0x00, 0x1F, 0xF3, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x0F, 0x44, 0x63, 0x63, 0x4E, 0x65, 0x74, 0x31, 0x00, 0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x17, 0x77, 0x77, 0x77, 0x2E, 0x44, 0x63, 0x63, 0x4E, 0x65, 0x74, 0x31, 0x2E, 0x63, 0x6F, 0x6D, 0x00])
    b4 = bytearray([0x01, 0x00, 0x00, 0x48, 0x80, 0x00, 0x01, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x34, 0x5A, 0x00, 0x03, 0x34, 0x5A, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x15, 0x75, 0x70, 0x63, 0x69, 0x2E, 0x67, 0x6D, 0x63, 0x63, 0x2E, 0x63, 0x6F, 0x6D, 0x70, 0x63, 0x69, 0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x10, 0x67, 0x6D, 0x63, 0x63, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x11, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x02])
    ori_data = b2
    diameter = Diameter()
    diameter.deserialize_from_buffer(ori_data)
    print(diameter.header.flag_r)
    ': :type avp443: Avp'
    avp443 = diameter.avp_at(873)
    avps = Avp.parse_grouped_avp(Avp.parse_grouped_avp(Avp.parse_grouped_avp(avp443)[0])[0])
    for avp in avps:
        avp.dump()
    buf = diameter.serialize_to_buffer()
    for i, word in enumerate(ori_data):
        if ori_data[i] != buf[i]:
            print('not equal %d' % i)
    dwr = DeviceWatchdogRequest()
    dwr.origin_host = 'gmcc.com'
    dwr.origin_realm = 'upci.gmcc.com'
    buf = dwr.serialize(1231231)


def test_cer(seq):
    cer = CapabilitiesExchangeRequest()
    cer.product_name = 'ACCT'
    cer.origin_host = 'charge3.ucp.gmcc.com'
    cer.origin_realm = 'charge3.ucp'
    cer.service_context_id = 'manager@huawei.com'
    cer.host_ip_address = '10.244.152.51'
    cer.vendor_id = 11
    cer.supported_vendor_id = 11
    cer.auth_application_id = 20
    cer.acct_application_id = 33
    cer.inband_security_id = 0
    cer.firmware_revision = 100
    byte_out = cer.serialize(seq)
    print(len(byte_out))
    Diameter.show_byte(byte_out)
    return byte_out


def test_deposit_ccr(seq):
    ccr = CreditControlRequest()
    ccr.timestamp = int(time.time()) / 1000
    ccr.product_name = 'ACCT'
    ccr.origin_host = 'charge3.ucp.gmcc.com'
    ccr.origin_realm = 'charge3.ucp'
    ccr.destination_host = 'DccProxy3'
    ccr.destination_realm = 'www.DccProxy3.com'
    ccr.service_context_id = 'manager@huawei.com'
    ccr.host_ip_address = '10.244.152.51'
    ccr.vendor_id = 11
    ccr.supported_vendor_id = 11
    ccr.auth_application_id = 20
    ccr.acct_application_id = 33
    ccr.inband_security_id = 0
    ccr.firmware_revision = 100
    ccr.subscription_id_data = '13726734050'
    ccr.service_type = '01010301'  # 01010401
    ccr.transactionid = 'NS119904398820161017105023861234'
    ccr.trade_time = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    ccr.serialno = ccr.transactionid
    ccr.oldserialno = ''
    ccr.recharge_number = ccr.subscription_id_data
    ccr.money_value = 1000
    ccr.accounttype = 3
    ccr.recharge_method = "04"
    ccr.ip = '192.168.0.48'
    ccr.port = 81000
    byte_out = ccr.serialize(seq)
    print(len(byte_out))
    Diameter.show_byte(byte_out)
    return byte_out


def test_reverse_ccr(seq):
    ccr = CreditControlRequest()
    ccr.timestamp = int(time.time()) / 1000
    ccr.product_name = 'ACCT'
    ccr.origin_host = 'charge3.ucp.gmcc.com'
    ccr.origin_realm = 'charge3.ucp'
    ccr.destination_host = 'DccProxy3'
    ccr.destination_realm = 'www.DccProxy3.com'
    ccr.service_context_id = 'manager@huawei.com'
    ccr.host_ip_address = '10.244.152.51'
    ccr.vendor_id = 11
    ccr.supported_vendor_id = 11
    ccr.auth_application_id = 20
    ccr.acct_application_id = 33
    ccr.inband_security_id = 0
    ccr.firmware_revision = 100
    ccr.subscription_id_data = '13726734050'
    ccr.service_type = '01010401'  # 01010401
    ccr.transactionid = 'NS119904398820161017105023861235'
    ccr.trade_time = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    ccr.serialno = ccr.transactionid
    ccr.oldserialno = 'NS119904398820161017105023861234'
    ccr.recharge_number = ccr.subscription_id_data
    ccr.money_value = 1000
    ccr.accounttype = 3
    ccr.recharge_method = "04"
    byte_out = ccr.serialize(seq)
    print(len(byte_out))
    Diameter.show_byte(byte_out)
    return byte_out


def test_dwr(seq):
    dwr = DeviceWatchdogRequest()
    dwr.origin_host = 'charge3.ucp.gmcc.com'
    dwr.origin_realm = 'charge3.ucp'
    byte_out = dwr.serialize(seq)
    print(len(byte_out))
    Diameter.show_byte(byte_out)
    return byte_out


def sock_recv_diameter(sock):
    header = sock.recv(20)
    dcc_header = DiameterHeader()
    dcc_header.deserialize_header(bytearray(header))
    body = sock.recv(dcc_header.length - 20)
    frame = bytearray(header + body)
    Diameter.show_byte(str(frame))
    if dcc_header.cmdcode == CONST.CODE_CCA:
        obj = CreditControlAnswer()
        obj.deserialize_from_buffer(frame)
    elif dcc_header.cmdcode == CONST.CODE_CEA:
        obj = CapabilitiesExchangeAnswer()
        obj.deserialize_from_buffer(frame)
    elif dcc_header.cmdcode == CONST.CODE_DWA:
        obj = DeviceWatchdogAnswer()
        obj.deserialize_from_buffer(frame)
    obj.extract_field()
    return obj


def test_boss_cer_dwr():
    import random
    sock = socket.socket()
    sock.connect(('192.168.0.48', 81000 - 65536))
    cer_byte = test_cer(random.randint(1, 100000))
    sock.send(cer_byte)
    obj = sock_recv_diameter(sock)
    print('\n')
    print('RESULT CODE: [%d]' % obj.result_code)
    # DWR
    print('=============>>>>>>>>>>>>>>DWR')
    dwr_byte = test_dwr(random.randint(1, 100000))
    sock.send(dwr_byte)
    obj2 = sock_recv_diameter(sock)
    print('RESULT CODE: [%d]' % obj2.result_code)
    dwr_byte = test_dwr(random.randint(1, 100000))
    sock.send(dwr_byte)
    obj2 = sock_recv_diameter(sock)
    print('RESULT CODE: [%d]' % obj2.result_code)


def test_boss_cer_dwr_cca_rev():
    import random
    sock = socket.socket()
    sock.connect(('192.168.0.48', 81000 - 65536))
    cer_byte = test_cer(random.randint(1, 100000))
    sock.send(cer_byte)
    obj = sock_recv_diameter(sock)
    print('\n')
    print('RESULT CODE: [%d]' % obj.result_code)
    # DWR
    print('=============>>>>>>>>>>>>>>DWR')
    ccr_byte = test_reverse_ccr(random.randint(1, 100000))
    sock.send(ccr_byte)
    obj2 = sock_recv_diameter(sock)
    print('RESULT CODE: [%d]' % obj2.result_code)


def test_boss_emulator(port):
    sock = socket.socket()
    sock.bind(('0.0.0.0', port))
    sock.listen(100)
    while True:
        cs, ca = sock.accept()


if __name__ == '__main__':
    test_boss_cer_dwr_cca_rev()
