#pragma once

#include <stdint.h>
#include <arpa/inet.h>
#include <utility>
#include <string>

// Constants 
// References : http://tools.ietf.org/html/rfc3748
static const uint32_t ETHERTYPE_PAE = 0x888e;
static const char PAE_GROUP_ADDR[] = "\x01\x80\xc2\x00\x00\x03";
static const char BROADCAST_ADDR[] = "\xff\xff\xff\xff\xff\xff";
static const char VERSION_INFO[] = "\x06\x07\x62jQ7SE8BZ3MqHhs3clMregcDY3Y=\x20\x20";

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
    std::string data;
};

struct eapol_t {
    uint8_t vers;
    uint8_t type;
    uint16_t eapol_len;
    eap_t eap;
};

#include <string>
inline std::string get_EAPOL(uint8_t type, const std::string& payload = std::string()) {
    std::string result;
    result.append((char *)(&EAPOL_VERSION), sizeof(EAPOL_VERSION));
    result.append((char *)(&type), sizeof(type));
    uint16_t len = static_cast<uint16_t>(payload.size());
    len = htons(len);
    result.append((char *)(&len), sizeof(len));
    result.append(payload);
    return std::move(result);
}

inline std::string get_EAP(uint8_t code, uint8_t id, uint8_t type, 
        const std::string& data = std::string()) {
    std::string result;
    uint16_t n = 4;
    result.append((char *)(&code), sizeof(code));
    result.append((char *)(&id), sizeof(id));
    if (code == EAP_SUCCESS || code == EAP_FAILURE) {
        n = htons(n);
        result.append((char *)(&n), sizeof(n));
    }
    else {
        n = 5 + data.length();
        n = htons(n);
        result.append((char *)(&n), sizeof(n));
        result.append((char *)(&type), sizeof(type));
        result.append(data);
    }
    return std::move(result);
}

inline std::string get_ethernet_header(const std::string& src, const std::string& dst, 
        uint16_t type) {
    type = htons(type);
    std::string result(dst);
    result.append(src);
    result.append((char *)(&type), sizeof(type));
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
