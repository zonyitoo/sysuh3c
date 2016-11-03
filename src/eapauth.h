#pragma once

#include "eapdef.h"
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <net/if.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __eapauth_t {
    char name[17];
    char password[17];
    int client_fd;
    uint8_t ethernet_header[14];
    struct sockaddr_ll addr;
    eap_method method;
} eapauth_t;

enum __eapauth_ret {
    EAPAUTH_OK = 0,
    EAPAUTH_ERR,
    EAPAUTH_FAIL,
    EAPAUTH_UNKNOWN
};

int eapauth_init(eapauth_t *user, const char *iface, eap_method method);
int eapauth_auth(const eapauth_t *user);
int eapauth_logoff(const eapauth_t *user);

void eapauth_redirect_promote(void (*)(int, const char *, ...));
void eapauth_set_status_listener(void (*)(int));

#ifdef __cplusplus
}
#endif
