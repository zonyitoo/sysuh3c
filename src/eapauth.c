/*
 * =====================================================================================
 *
 *       Filename:  eapauth.c
 *
 *    Description:  eapauth client
 *
 *        Version:  1.0
 *        Created:  2013年05月24日 01时38分41秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Tyler Chung
 *   Organization:  SYSU
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include "eapdef.h"
#include "eapauth.h"
#include "eaputils.h"
#include "md5.h"
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

int send_start(const eapauth_t *user);
int send_logoff(const eapauth_t *user);
int send_response_id(const eapauth_t *user, uint8_t packet_id);
int send_response_h3c(const eapauth_t *user, uint8_t packet_id);
int send_response_md5(const eapauth_t *user, uint8_t packet_id, const uint8_t *md5data);

int eap_handler(const eapauth_t *user, const eapol_t *data);
int client_send(const eapauth_t *user, const eapol_t *data);
int client_recv(const eapauth_t *user, eapol_t *data);

void set_socket_timeout(const eapauth_t *user, time_t sec);

void status_notify_func(int statno) {
    fprintf(stderr, "%s\n", strstat(statno));
}

void display_promote_func(int priority, const char *format, ...) {
    va_list arglist;
    va_start(arglist, format);
    fprintf(stderr, format, arglist);
    fprintf(stderr, "\n");
    va_end(arglist);
}

static void (*status_notify)(int) = status_notify_func;
static void (*display_promote)(int, const char *, ...) = display_promote_func;

int eapauth_init(eapauth_t *user, const char *iface, eap_method method) {
    uint8_t mac_addr_buf[6] = {0};
    struct timeval timeout;
    struct ifreq ifr; 
    size_t i;

    if ((user->client_fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))) < 0) {
        display_promote(LOG_ERR, "socket %s", strerror(errno));
        return EAPAUTH_ERR;
    }

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(user->client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

    if (ioctl(user->client_fd, SIOCGIFFLAGS, &ifr) < 0) {
        display_promote(LOG_ERR, "ioctl %s", strerror(errno));
        return EAPAUTH_ERR;
    }

    if ((ifr.ifr_flags & IFF_UP) == 0) {
        shutdown(user->client_fd, SHUT_RDWR);
        display_promote(LOG_ERR, "Interface %s is not avaliable",
                __func__, __LINE__, iface);
        return EAPAUTH_ERR;
    }

    if (ioctl(user->client_fd, SIOCGIFHWADDR, &ifr) < 0) {
        display_promote(LOG_ERR, "ioctl %s", strerror(errno));
        return EAPAUTH_ERR;
    }

    for (i = 0; i < 6; ++ i)
        mac_addr_buf[i] = ifr.ifr_hwaddr.sa_data[i];

    if (ioctl(user->client_fd, SIOCGIFINDEX, &ifr) < 0) {
        display_promote(LOG_ERR, "ioctl %s", strerror(errno));
        return EAPAUTH_ERR;
    }

    memset(&user->addr, 0, sizeof(user->addr));
    user->addr.sll_family = AF_PACKET;
    user->addr.sll_ifindex = ifr.ifr_ifindex;
    user->addr.sll_protocol = htons(ETHERTYPE_PAE);

    if (bind(user->client_fd, (struct sockaddr *) &user->addr, sizeof(user->addr)) == -1) {
        display_promote(LOG_ERR, "bind %s", strerror(errno));
        return EAPAUTH_ERR;
    }

    get_ethernet_header(mac_addr_buf, PAE_GROUP_ADDR, ETHERTYPE_PAE, user->ethernet_header);

    user->method = method;

    return EAPAUTH_OK;
}

int eapauth_auth(const eapauth_t *user) {
    char buf[1600] = {0};

    set_socket_timeout(user, 5);
    send_start(user);
    status_notify(EAPAUTH_AUTH_START);
    while (1) {
        eapol_t packet;
        packet.eap.data = buf;
        int ret = client_recv(user, &packet);
        if (ret == EAPAUTH_ERR) return ret;

        ret = eap_handler(user, &packet);
        if (ret == EAPAUTH_ERR || ret == EAPAUTH_FAIL) return ret;
    }
    return EAPAUTH_OK;
}

void eapauth_set_status_listener(void (*func)(int)) {
    status_notify = func;
}

void eapauth_redirect_promote(void (*func)(int, const char*, ...)) {
    display_promote = func;
}

int client_send(const eapauth_t *user, const eapol_t *data) {
    uint8_t buf[2048] = {0};
    uint8_t *p_buf = buf;
    int len;
    uint16_t tmp;

    if (user == NULL || data == NULL) return EAPAUTH_ERR;

    memcpy(p_buf, user->ethernet_header, sizeof(user->ethernet_header));
    p_buf += sizeof(user->ethernet_header);

    *p_buf ++ = data->vers;
    *p_buf ++ = data->type;
    tmp = htons(data->eapol_len);
    memcpy(p_buf, &tmp, sizeof(tmp));
    p_buf += sizeof(data->eapol_len);
    if (data->eapol_len != 0) {
        *p_buf ++ = data->eap.code;
        *p_buf ++ = data->eap.id;
        tmp = htons(data->eap.eap_len);
        memcpy(p_buf, &tmp, sizeof(tmp));
        p_buf += sizeof(data->eap.eap_len);
        if (data->eap.eap_len > 4 && data->eap.data != NULL) {
            *p_buf ++ = data->eap.reqtype;
            memcpy(p_buf, data->eap.data, data->eap.eap_len - 5);
            p_buf += data->eap.eap_len - 5;
        }
    }
    len = sendto(user->client_fd, buf, p_buf - buf, MSG_NOSIGNAL,
            (struct sockaddr *) &user->addr, sizeof(user->addr));
    if (len <= 0) return EAPAUTH_ERR;
    return EAPAUTH_OK;
}

int client_recv(const eapauth_t *user, eapol_t *data) {
    char buf[1600] = {0};
    socklen_t sock_addr_len = sizeof(user->addr);
    int ret = recvfrom(user->client_fd, buf, sizeof(buf), 0,
                        (struct sockaddr *) &user->addr, &sock_addr_len);
    if (ret <= 0 || data == NULL)
        return EAPAUTH_ERR;

    // remove header
    const uint8_t *ptr = buf + sizeof(user->ethernet_header);
    data->vers = ptr[0];
    data->type = ptr[1];
    data->eapol_len = ntohs(*((uint16_t *)(&ptr[2])));
    if (data->eapol_len != 0) {
        data->eap.code = ptr[4];
        data->eap.id = ptr[5];
        data->eap.eap_len = ntohs(*((uint16_t *)(&ptr[6])));
        if (data->eap.eap_len > 4) {
            data->eap.reqtype = ptr[8];
            memcpy(data->eap.data, ptr + 10, data->eap.eap_len);
        }
    }

    return EAPAUTH_OK;
}

int send_start(const eapauth_t *user) {
    if (user == NULL) return EAPAUTH_ERR;

    eapol_t eapol_start;
    eapol_start.vers = EAPOL_VERSION;
    eapol_start.type = EAPOL_START;
    eapol_start.eapol_len = 0;
    return client_send(user, &eapol_start);
}

int send_logoff(const eapauth_t *user) {
    if (user == NULL) return EAPAUTH_ERR;

    eapol_t eapol_logoff;
    eapol_logoff.vers = EAPOL_VERSION;
    eapol_logoff.type = EAPOL_LOGOFF;
    eapol_logoff.eapol_len = 0;

    return client_send(user, &eapol_logoff);
}

int send_response_id(const eapauth_t *user, uint8_t packet_id) {
    uint8_t eappacket[128] = {0};

    if (user == NULL) return EAPAUTH_ERR;

    memcpy(eappacket, VERSION_INFO, sizeof(VERSION_INFO));
    strcpy(eappacket + sizeof(VERSION_INFO), user->name);

    eapol_t eapol_id;
    eapol_id.vers = EAPOL_VERSION;
    eapol_id.type = EAPOL_EAPPACKET;
    eapol_id.eap.code = EAP_RESPONSE;
    eapol_id.eap.id = packet_id;
    eapol_id.eap.reqtype = EAP_TYPE_ID;
    eapol_id.eap.data = eappacket;
    eapol_id.eap.eap_len = sizeof(VERSION_INFO) + strlen(user->name) + 5;
    eapol_id.eapol_len = eapol_id.eap.eap_len;
    return client_send(user, &eapol_id);
}

int send_response_h3c(const eapauth_t *user, uint8_t packet_id) {

    uint8_t packetbuf[128] = {0};

    if (user == NULL) return EAPAUTH_ERR;

    packetbuf[0] = strlen(user->password);
    strcpy(packetbuf + 1, user->password);
    strcpy(packetbuf + packetbuf[0] + 1, user->name);

    eapol_t eap_h3c;
    eap_h3c.vers = EAPOL_VERSION;
    eap_h3c.type = EAPOL_EAPPACKET;
    eap_h3c.eap.code = EAP_RESPONSE;
    eap_h3c.eap.id = packet_id;
    eap_h3c.eap.reqtype = EAP_TYPE_H3C;
    eap_h3c.eap.data = packetbuf;
    eap_h3c.eap.eap_len = packetbuf[0] + strlen(user->name) + 6;
    eap_h3c.eapol_len = eap_h3c.eap.eap_len;
    return client_send(user, &eap_h3c);
}

int send_response_md5(const eapauth_t *user, uint8_t packet_id, const uint8_t *md5data) {
    uint8_t chap[16] = {0};
    uint8_t chapbuf[128] = {0}; // id + password + md5data
    size_t chapbuflen, passwordlen, i;
    uint8_t packetbuf[128] = {0};

    if (user == NULL || md5data == NULL) return EAPAUTH_ERR;

    switch(user->method) {
        case EAP_METHOD_XOR: // xor(password, md5data)
            strcpy(chap, user->password);
            for (i = 0; i < 16; ++ i)
                chap[i] ^= md5data[i];
            break;
        case EAP_METHOD_MD5: // MD5(id + password + md5data)
        default:
            passwordlen = strlen(user->password);
            chapbuflen = 1 + passwordlen + 16;

            chapbuf[0] = packet_id;
            memcpy(chapbuf + 1, user->password, passwordlen);
            memcpy(chapbuf + 1 + passwordlen, md5data, 16);

            MD5_CTX context;
            MD5_Init(&context);
            MD5_Update(&context, chapbuf, chapbuflen);
            MD5_Final(chap, &context);
            break;
    }

    packetbuf[0] = sizeof(chap); // Value-Size
    memcpy(packetbuf + 1, chap, sizeof(chap)); // MD5 Area
    strcpy(packetbuf + 1 + sizeof(chap), user->name); // Username

    eapol_t eap_md5;
    eap_md5.vers = EAPOL_VERSION;
    eap_md5.type = EAPOL_EAPPACKET;
    eap_md5.eap.code = EAP_RESPONSE;
    eap_md5.eap.id = packet_id;
    eap_md5.eap.reqtype = EAP_TYPE_MD5;
    eap_md5.eap.data = packetbuf;
    eap_md5.eap.eap_len = sizeof(chap) + strlen(user->name) + 6;
    eap_md5.eapol_len = eap_md5.eap.eap_len;
    return client_send(user, &eap_md5);
}

void set_socket_timeout(const eapauth_t *user, time_t sec) {
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = 0;
    setsockopt(user->client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
}

int eap_handler(const eapauth_t *user, const eapol_t *eapol_packet) {
    if (eapol_packet == NULL || user == NULL) return EAPAUTH_ERR;
    if (eapol_packet->type != EAPOL_EAPPACKET) {
        status_notify(EAPAUTH_UNKNOWN_PACKET_TYPE);
        return EAPAUTH_UNKNOWN;
    }

    switch (eapol_packet->eap.code) {
        case EAP_SUCCESS:
            status_notify(EAPAUTH_EAP_SUCCESS);
            set_socket_timeout(user, 30);
            break;
        case EAP_FAILURE:
            status_notify(EAPAUTH_EAP_FAILURE);
            set_socket_timeout(user, 5);
            return EAPAUTH_FAIL;
        case EAP_RESPONSE:
            status_notify(EAPAUTH_EAP_RESPONSE);
            break;
        case EAP_REQUEST:
            switch (eapol_packet->eap.reqtype) {
                case EAP_TYPE_ID:
                    status_notify(EAPAUTH_AUTH_ID);
                    if (send_response_id(user, eapol_packet->eap.id) != 0) {
                        display_promote(LOG_ERR, "send_response_id error");
                        return EAPAUTH_ERR;
                    }
                    break;
                case EAP_TYPE_H3C:
                    status_notify(EAPAUTH_AUTH_H3C);
                    if (send_response_h3c(user, eapol_packet->eap.id) != 0) {
                        display_promote(LOG_ERR, "send_response_h3c error");
                        return EAPAUTH_ERR;
                    }
                    break;
                case EAP_TYPE_MD5:
                    status_notify(EAPAUTH_AUTH_MD5);
                    if (send_response_md5(user, eapol_packet->eap.id, eapol_packet->eap.data) != 0) {
                        display_promote(LOG_ERR, "send_response_md5 error");
                        return EAPAUTH_ERR;
                    }
                    break;
                default:
                    status_notify(EAPAUTH_UNKNOWN_REQUEST_TYPE);
            }
            break;
        case 10:
            break;
        default:
            status_notify(EAPAUTH_UNKNOWN_EAP_CODE);
    }
    return EAPAUTH_OK;
}

int eapauth_logoff(const eapauth_t *user) {
    if (user == NULL) return EAPAUTH_ERR;
    
    return send_logoff(user);
}
