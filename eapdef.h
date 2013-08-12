#pragma once

#include <stdint.h>
#include <arpa/inet.h>
#include <utility>
#include <string>
#include <array>
#include <vector>

// Constants 
// References : http://tools.ietf.org/html/rfc3748
static const uint32_t ETHERTYPE_PAE = 0x888e;

typedef std::array<uint8_t, 6> mac_addr_t;
static const mac_addr_t PAE_GROUP_ADDR = {{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}};
static const mac_addr_t BROADCAST_ADDR = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
static const std::array<uint8_t, 32> VERSION_INFO = 
                                        {{0x06, 0x07, 'b', 'j', 'Q', '7', 'S', 'E', '8', 'B',
                                        'Z', '3', 'M', 'q', 'H', 'h', 's', '3', 'c', 'l', 
                                        'M', 'r', 'e', 'g', 'c', 'D', 'Y', '3', 'Y', '=',
                                        0x20, 0x20}};

static const uint8_t EAPOL_VERSION = 1;
static const uint8_t EAPOL_EAPPACKET = 0;

// Packet info for EAPOL_EAPPACKET
static const uint8_t EAPOL_START = 1;
static const uint8_t EAPOL_LOGOFF = 2;
static const uint8_t EAPOL_KEY = 3;
static const uint8_t EAPOL_ASF = 4;

static const uint8_t EAP_REQUEST = 1;
static const uint8_t EAP_RESPONSE = 2;
static const uint8_t EAP_SUCCESS = 3;
static const uint8_t EAP_FAILURE = 4;

// Packet info followed by EAP_RESPONSE
// 1            Identity
// 2            Notification
// 3            Nak (Response Only)
// 4            MD5-Challenge
// 5            One Time Password (OTP)
// 6            Generic Token Card (GTC)
// 254          Expanded Types
// 255          Experimental use
static const uint8_t EAP_TYPE_ID = 1;       // identity
static const uint8_t EAP_TYPE_MD5 = 4;      // md5 challenge
static const uint8_t EAP_TYPE_H3C = 7;      // H3C eap packet (used for SYSU east campus)

struct eap_t {
    uint8_t code;
    uint8_t id;
    uint16_t eap_len;
    uint8_t reqtype;
    uint8_t datalen;
    std::vector<uint8_t> data;
};

struct eapol_t {
    uint8_t vers;
    uint8_t type;
    uint16_t eapol_len;
    eap_t eap;
};

template <typename T>
inline void Append(std::vector<uint8_t>& vec, const T data) {
    uint8_t * pnt = (uint8_t *)(&data);
    for (size_t i = 0; i < sizeof(data); ++ i)
        vec.push_back(*(pnt ++));
}

inline void get_EAPOL(std::vector<uint8_t>& result, uint8_t type, const std::vector<uint8_t>& payload = std::vector<uint8_t>()) {
    result.push_back(EAPOL_VERSION);
    Append(result, type);
    uint16_t len = static_cast<uint16_t>(payload.size());
    len = htons(len);
    Append(result, len);
    result.insert(result.end(), payload.begin(), payload.end());
}

inline std::vector<uint8_t> get_EAP(uint8_t code, uint8_t id, uint8_t type,  
        const std::vector<uint8_t>& data = std::vector<uint8_t>()) {
    std::vector<uint8_t> result;
    uint16_t n = 4;
    Append(result, code);
    Append(result, id);
    if (code == EAP_SUCCESS || code == EAP_FAILURE) {
        n = htons(n);
        Append(result, n);
    }
    else {
        n = 5 + data.size();
        n = htons(n);
        Append(result, n);
        Append(result, type);
        result.insert(result.end(), data.begin(), data.end());
    }
    return std::move(result);
}

inline std::vector<uint8_t> get_ethernet_header(const mac_addr_t& src, const mac_addr_t& dst, uint16_t type) {
    type = htons(type);
    std::vector<uint8_t> result;
    result.assign(dst.begin(), dst.end());
    result.insert(result.end(), src.begin(), src.end());
    uint8_t *pnt = (uint8_t *)(&type);
    result.push_back(*pnt);
    result.push_back(*(pnt + 1));
    return std::move(result);
}

enum {
    EAPAUTH_UNKNOWN_REQUEST_TYPE = -3,
    EAPAUTH_UNKNOWN_PACKET_TYPE = -2,
    EAPAUTH_UNKNOWN_EAP_CODE = -1,
    EAPAUTH_AUTH_AUTORETRY = 0,
    EAPAUTH_EAP_SUCCESS = 1,
    EAPAUTH_EAP_FAILURE,
    EAPAUTH_EAP_RESPONSE,
    EAPAUTH_AUTH_START,
    EAPAUTH_AUTH_ID,
    EAPAUTH_AUTH_H3C,
    EAPAUTH_AUTH_MD5
};

inline std::string strstat(int statno) {
    switch (statno) {
    case EAPAUTH_UNKNOWN_REQUEST_TYPE:
        return std::string("Unknown Request Type");
    case EAPAUTH_UNKNOWN_PACKET_TYPE:
        return std::string("Unknown Packet Type");
    case EAPAUTH_UNKNOWN_EAP_CODE:
        return std::string("Unknown EAP Code");
    case EAPAUTH_AUTH_AUTORETRY:
        return std::string("EAP Failure, Autoretry");
    case EAPAUTH_EAP_SUCCESS:
        return std::string("EAP Success");
    case EAPAUTH_EAP_FAILURE:
        return std::string("EAP Failure");
    case EAPAUTH_EAP_RESPONSE:
        return std::string("EAP Response");
    case EAPAUTH_AUTH_START:
        return std::string("EAP Auth Start");
    case EAPAUTH_AUTH_ID:
        return std::string("Got EAP Request for Identity");
    case EAPAUTH_AUTH_H3C:
        return std::string("Got EAP Request for Allocation");
    case EAPAUTH_AUTH_MD5:
        return std::string("Got EAP Request for MD5-Challenge");
    default:
        return std::string("Unknown Status Code");
    }
}
