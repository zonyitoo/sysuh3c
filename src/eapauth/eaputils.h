/*
 * =====================================================================================
 *
 *       Filename:  eaputils.h
 *
 *    Description:  utilities
 *
 *        Version:  1.0
 *        Created:  2013年08月18日 02时02分51秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Elton Chung
 *   Organization:  SYSU
 *
 * =====================================================================================
 */

#pragma once

#include "eapdef.h"
#include <array>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>

#ifdef SYSTEM_LINUX
#include <netpacket/packet.h>
#elif SYSTEM_DARWIN
#   include <net/if_dl.h>
#   include <net/bpf.h>
#endif

namespace sysuh3c {

class EAPClient {
public:
    EAPClient(const std::string &iface);
    ~EAPClient();

    EAPClient &operator >> (eapol_t &eapol);
    EAPClient &operator << (const eapol_t &eapol);

    EAPClient &recv(eapol_t &eapol);
    EAPClient &send(const eapol_t &eapol);

    void set_timeout(int timeval);

private:
    std::array<uint8_t, sizeof(ethernet_header_t)> ethernet_header;
    std::vector<uint8_t> recv_buf;

    #ifdef SYSTEM_LINUX
    int client_fd;
    struct sockaddr_ll sock_addr;
    #elif SYSTEM_DARWIN
    struct sockaddr_dl sock_addr;
    mac_addr_t mac_addr;
    int bpf_fd;
    struct timeval timeout;
    #endif
};

}
