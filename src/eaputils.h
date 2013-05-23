#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

const char * strstat(int statno);
char * get_ethernet_header(const uint8_t src[6], const uint8_t dst[6], uint16_t type, 
        char * header);
uint8_t * get_EAP(uint8_t code, uint8_t id, uint8_t type, const uint8_t *data, uint16_t datalen,
        uint8_t * eap);
uint8_t * get_EAPOL(uint8_t type, const uint8_t * payload, uint16_t len, uint8_t * eapol);

#ifdef __cplusplus
}
#endif
