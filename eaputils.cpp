/*
 * =====================================================================================
 *
 *       Filename:  eaputils.cpp
 *
 *    Description:  utilities
 *
 *        Version:  1.0
 *        Created:  2013年08月18日 11时16分48秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Elton Chung
 *   Organization:  SYSU
 *
 * =====================================================================================
 */

#include "eaputils.h"
#include <cstring>
#include <algorithm>
#include <vector>
#include <iostream>
#include <cstdio>

EAPClient::EAPClient(const std::string& iface) {
    if ((client_fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))) < 0) {
        perror("socket");
        abort();
    }

    //setsockopt(client_fd, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.length());
    
    // When authorizing, timeout = 5s
    set_timeout(5);

    // Check interface is avaliable or not
    struct ifreq ifr; 
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), sizeof(ifr.ifr_name));
    if (ioctl(client_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl");
        abort();
    }
    if ((ifr.ifr_flags & IFF_UP) == 0) {
        shutdown(client_fd, SHUT_RDWR);
        throw EAPAuthException("Interface is not available");
    }

    // Get MAC address
    if (ioctl(client_fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        abort();
    }
    mac_addr_t mac_addr;
    for (size_t i = 0; i < mac_addr.size(); ++ i)
        mac_addr[i] = ifr.ifr_hwaddr.sa_data[i];

    if (ioctl(client_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        abort();
    }

    // Bind Socket
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sll_family = AF_PACKET;
    sock_addr.sll_ifindex = ifr.ifr_ifindex;
    sock_addr.sll_protocol = htons(ETHERTYPE_PAE);
    if (bind(client_fd, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) == -1) {
        perror("bind");
        abort();
    }

    // Generate ethernet header
    std::copy(PAE_GROUP_ADDR.begin(), PAE_GROUP_ADDR.end(), ethernet_header.begin());    
    std::array<uint8_t, 14>::iterator itr = ethernet_header.begin();
    std::advance(itr, PAE_GROUP_ADDR.size());
    std::copy(mac_addr.begin(), mac_addr.end(), itr);
    uint16_t etype = htons(ETHERTYPE_PAE);
    memcpy(ethernet_header.data() + PAE_GROUP_ADDR.size() + mac_addr.size(),
            (char *) &etype, sizeof(etype));
}

EAPClient::~EAPClient() {
    shutdown(client_fd, SHUT_RDWR);
}

EAPClient& EAPClient::operator >> (eapol_t& eapol) {
    return this->recv(eapol);
}

EAPClient& EAPClient::operator << (const eapol_t& eapol) {
    return this->send(eapol);
}

EAPClient& EAPClient::recv(eapol_t& eapol) {
    char rcvbuf[1600] = {0};
    socklen_t sock_addr_len = sizeof(sock_addr);
    int len = recvfrom(client_fd, rcvbuf, sizeof(rcvbuf), 0,
            (struct sockaddr *) &sock_addr, &sock_addr_len);

    if (len <= 0) throw EAPAuthException("Socket recv error");

    // Remove header
    char *buf = rcvbuf + 14;
    if (len - 14 == 0) return *this;

    eapol.vers = buf[0];
    eapol.type = buf[1];
    eapol.eapol_len = ntohs(*((uint16_t *) &buf[2]));

    if (eapol.eapol_len <= 0) return *this;

    eapol.eap.reset(new eap_t);
    eapol.eap->code = buf[4];
    eapol.eap->id = buf[5];
    eapol.eap->eap_len = ntohs(*(uint16_t *) &buf[6]);
    if (eapol.eap->eap_len > 4) {
        eapol.eap->reqtype = buf[8];
        //copy(buf + 9, buf + len - 5, eapol.eap->data.begin());
        for (int i = 10; i < len - 14; ++ i)
            eapol.eap->data.push_back(buf[i]);
    }

    return *this;
}

EAPClient& EAPClient::send(const eapol_t& eapol) {
    std::string buf;
    buf.assign(ethernet_header.begin(), ethernet_header.end());
    buf += eapol.to_buf();

    int len = sendto(client_fd, buf.c_str(), buf.length(), MSG_NOSIGNAL, 
            (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("EAPClient send error");

    return *this;
}

void EAPClient::set_timeout(__time_t tv_sec) {
    struct timeval timeout;
    timeout.tv_sec = tv_sec;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
}
