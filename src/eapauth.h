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
    _Bool has_sent_logoff;
    uint8_t ethernet_header[14];
    struct sockaddr_ll addr;
} eapauth_t;

void eapauth_init(eapauth_t *user, const char *iface);
int eapauth_auth(eapauth_t *user);
int eapauth_logoff(eapauth_t *user);

void eapauth_redirect_promote(void (*)(const char *, ...));
void eapauth_set_status_listener(void (*)(int));

#ifdef __cplusplus
}
#endif
