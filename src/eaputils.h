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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netpacket/packet.h>

class EAPClient {
    public:
        EAPClient(const std::string& iface);
        ~EAPClient();

        EAPClient& operator >> (eapol_t& eapol);
        EAPClient& operator << (const eapol_t& eapol);

        EAPClient& recv(eapol_t& eapol);
        EAPClient& send(const eapol_t& eapol);

        void set_timeout(__time_t timeval);

    private:
        std::array<uint8_t, 14> ethernet_header;

        int client_fd;
        struct sockaddr_ll sock_addr;
};
