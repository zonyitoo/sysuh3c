/*
 * =====================================================================================
 *
 *       Filename:  eaputils.c
 *
 *    Description:  eaputils
 *
 *        Version:  1.0
 *        Created:  2013年05月24日 03时05分21秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Tyler Chung
 *   Organization:  SYSU
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "eapdef.h"

uint8_t * get_EAPOL(uint8_t type, const uint8_t * payload, uint16_t len, uint8_t * eapol) {
    if (eapol == NULL) return NULL;
    memcpy(eapol, &EAPOL_VERSION, sizeof(EAPOL_VERSION));
    eapol += sizeof(EAPOL_VERSION);
    *eapol ++ = type;
    len = htons(len);
    memcpy(eapol, &len, sizeof(len));
    eapol += sizeof(len);
    memcpy(eapol, payload, len);
    eapol += len;
    return eapol;
}

uint8_t * get_EAP(uint8_t code, uint8_t id, uint8_t type, const uint8_t *data, uint16_t datalen,
        uint8_t * eap) {
    uint16_t n = 4;
    if (eap == NULL) return NULL;
    *eap ++ = code;
    *eap ++ = id;
    if (code == EAP_SUCCESS || code == EAP_FAILURE) {
        n = htons(n);
        memcpy(eap, &n, sizeof(n));
        eap += sizeof(n);
    }
    else {
        n = 5 + datalen;
        memcpy(eap, &n, sizeof(n));
        eap += sizeof(n);
        *eap ++ = type;
        memcpy(eap, data, datalen);
        eap += datalen;
    }
    return eap;
}

char * get_ethernet_header(const uint8_t src[6], const uint8_t dst[6], uint16_t type, 
        char * header) {
    if (header == NULL) return NULL;
    type = htons(type);
    memcpy(header, dst, 6);
    header += 6;
    memcpy(header, src, 6);
    header += 6;
    memcpy(header, &type, sizeof(type));
    header += sizeof(type);
    return header;
}

const char * strstat(int statno) {
    switch (statno) {
    case EAPAUTH_UNKNOWN_REQUEST_TYPE:
        return "Unknown Request Type";
    case EAPAUTH_UNKNOWN_PACKET_TYPE:
        return "Unknown Packet Type";
    case EAPAUTH_UNKNOWN_EAP_CODE:
        return "Unknown EAP Code";
    case EAPAUTH_AUTH_AUTORETRY:
        return "EAP Failure, Autoretry";
    case EAPAUTH_EAP_SUCCESS:
        return "EAP Success";
    case EAPAUTH_EAP_FAILURE:
        return "EAP Failure";
    case EAPAUTH_EAP_RESPONSE:
        return "EAP Response";
    case EAPAUTH_AUTH_START:
        return "EAP Auth Start";
    case EAPAUTH_AUTH_ID:
        return "Got EAP Request for Identity";
    case EAPAUTH_AUTH_H3C:
        return "Got EAP Request for Allocation";
    case EAPAUTH_AUTH_MD5:
        return "Got EAP Request for MD5-Challenge";
    default:
        return "Unknown Status Code";
    }
}
