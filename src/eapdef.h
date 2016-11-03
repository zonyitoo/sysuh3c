#pragma once

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

// Constants 
// References : http://tools.ietf.org/html/rfc3748
static const uint32_t ETHERTYPE_PAE = 0x888e;
static const uint8_t PAE_GROUP_ADDR[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
static const uint8_t BROADCAST_ADDR[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t VERSION_INFO[] = {0x06, 0x07, 'b', 'j', 'Q', '7', 'S', 'E', '8', 'B',
                                        'Z', '3', 'M', 'q', 'H', 'h', 's', '3', 'c', 'l', 
                                        'M', 'r', 'e', 'g', 'c', 'D', 'Y', '3', 'Y', '=',
                                        0x20, 0x20};

static const uint8_t EAPOL_VERSION = 1;
static const uint8_t EAPOL_EAPPACKET = 0;

// Packet info for EAPOL_EAPPACKET
static const uint8_t EAPOL_START = 1;
static const uint8_t EAPOL_LOGOFF = 2;
static const uint8_t EAPOL_KEY = 3;
static const uint8_t EAPOL_ASF = 4;

#ifdef __cplusplus
extern "C" {
#endif

enum __eap_code {
    EAP_REQUEST = 1,
    EAP_RESPONSE = 2,
    EAP_SUCCESS = 3,
    EAP_FAILURE = 4
};

// Packet info followed by EAP_RESPONSE
// 1            Identity
// 2            Notification
// 3            Nak (Response Only)
// 4            MD5-Challenge
// 5            One Time Password (OTP)
// 6            Generic Token Card (GTC)
// 254          Expanded Types
// 255          Experimental use
enum __eap_type {
    EAP_TYPE_ID = 1,                        // identity
    EAP_TYPE_MD5 = 4,                       // md5 challenge
    EAP_TYPE_H3C = 7                        // H3C eap packet (used for SYSU east campus)
};

typedef enum __eap_method {
    EAP_METHOD_XOR,
    EAP_METHOD_MD5
} eap_method;

typedef struct __eap_t {
    uint8_t code;
    uint8_t id;
    uint16_t eap_len;
    uint8_t reqtype;
    uint8_t * data;
} eap_t;

typedef struct __eapol_t {
    uint8_t vers;
    uint8_t type;
    uint16_t eapol_len;
    eap_t eap;
} eapol_t;

enum __status_code {
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

#ifdef __cplusplus
}
#endif
