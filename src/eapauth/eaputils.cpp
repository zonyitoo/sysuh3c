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

#ifdef SYSTEM_DARWIN
    #include <net/if_dl.h>
    #include <sys/sysctl.h>
    #include <sys/select.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

namespace sysuh3c {

EAPClient::EAPClient(const std::string &iface) {

    mac_addr_t mac_addr;

#ifdef SYSTEM_LINUX
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

    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, sizeof(mac_addr));

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

    recv_buf.resize(1600);

#elif SYSTEM_DARWIN // FOR Darwin
    
    FILE* fp;
    char bpf_num_str[80];
    fp=popen("sysctl debug.bpf_maxdevices","r");
    fgets(bpf_num_str,sizeof(bpf_num_str),fp);
    int bpf_num = strtol(bpf_num_str + 22, NULL, 0);
    for (int i = 0; i < bpf_num; i++) {
        std::string bpf_path = "/dev/bpf" + std::to_string(i);
        if ((bpf_fd = open(bpf_path.c_str(), O_RDWR)) >= 0)
            break;
        if (i == bpf_num - 1) {
            perror("open");
            abort();
        }
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), sizeof(ifr.ifr_name));

    struct bpf_program bpfpro;
    this->timeout.tv_sec = 30;
    this->timeout.tv_usec = 0;
    const int ci_immediate=1, cmplt = 1;
    size_t buf_len, set_buf_len = 128;
    if (ioctl(bpf_fd, BIOCSBLEN, &set_buf_len) == -1
        || ioctl(bpf_fd, BIOCSETIF, &ifr) == -1
        || ioctl(bpf_fd, BIOCIMMEDIATE, &ci_immediate) == -1
        || ioctl(bpf_fd, BIOCSHDRCMPLT, &cmplt) == -1
        || ioctl(bpf_fd, BIOCGBLEN, &buf_len) == -1
        || ioctl(bpf_fd, BIOCSRTIMEOUT, &this->timeout) == -1) {
        perror("ioctl");
        close(bpf_fd);
        abort();
    }

    recv_buf.resize(buf_len);

    // Get MAC address
    int ifindex;
    if ((ifindex = if_nametoindex(iface.c_str())) == 0) {
        perror("if_nametoindex");
        close(bpf_fd);
        abort();
    }
    int mib[6] = {CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, ifindex};
    size_t sysctl_len;
    if (sysctl(mib, 6, nullptr, &sysctl_len, nullptr, 0) < 0) {
        perror("sysctl 1 error");
        close(bpf_fd);
        abort();
    }
    char *macbuf = new char[sysctl_len];
    if (sysctl(mib, 6, macbuf, &sysctl_len, nullptr, 0) < 0) {
        perror("sysctl 1 error");
        close(bpf_fd);
        delete []macbuf;
        abort();
    }
    struct if_msghdr *ifm = (struct if_msghdr *) macbuf;
    struct sockaddr_dl *sdl = (struct sockaddr_dl *)(ifm + 1);
    unsigned char *ptr = (unsigned char *) LLADDR(sdl);
    memcpy(mac_addr, ptr, sizeof(mac_addr));
    delete []macbuf;

    // save mac address
    memcpy(this->mac_addr, mac_addr, 6);

#else
#error SYSUH3C doesn't support your platform.
#endif

    // Generate ethernet header

    using std::begin;
    using std::end;
    using std::copy;
    using std::array;
    using std::advance;
    copy(begin(PAE_GROUP_ADDR), end(PAE_GROUP_ADDR), ethernet_header.begin());
    array<uint8_t, 14>::iterator itr = ethernet_header.begin();
    advance(itr, sizeof(PAE_GROUP_ADDR));
    copy(begin(mac_addr), end(mac_addr), itr);
    uint16_t etype = htons(ETHERTYPE_PAE);
    *(uint16_t *)(ethernet_header.data() + sizeof(PAE_GROUP_ADDR) + sizeof(mac_addr)) = etype;

}

EAPClient::~EAPClient() {
    #ifdef SYSTEM_LINUX
    shutdown(client_fd, SHUT_RDWR);
    #elif SYSTEM_DARWIN
    close(bpf_fd);
    #endif
}

EAPClient &EAPClient::operator >> (eapol_t &eapol) {
    return this->recv(eapol);
}

EAPClient &EAPClient::operator << (const eapol_t &eapol) {
    return this->send(eapol);
}

EAPClient &EAPClient::recv(eapol_t &eapol) {

    int len;

    #ifdef SYSTEM_LINUX
    socklen_t sock_addr_len = sizeof(sock_addr);
    if ((len = recvfrom(client_fd, recv_buf.data(), recv_buf.size(), 0,
                       (struct sockaddr *) &sock_addr, &sock_addr_len)) <= 0) {
        throw EAPAuthException("Socket recv error");
    }
    // Remove header
    uint8_t *buf = recv_buf.data() + sizeof(ethernet_header_t);
    #elif SYSTEM_DARWIN
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(bpf_fd, &readset);
    ioctl(bpf_fd, BIOCFLUSH);

    if (select(bpf_fd + 1, &readset, nullptr, nullptr, &timeout) != 1) {
        perror("select");
        throw EAPAuthException(strerror(errno));
    }

    if ((len = read(bpf_fd, recv_buf.data(), recv_buf.size())) == -1) {
        throw EAPAuthException("BPF read error");
    }

    // check mac address and header
    ethernet_header_t *ethernet_header = (ethernet_header_t *)(recv_buf.data() + 18);
    if (memcmp(ethernet_header->dest, this->mac_addr, sizeof(mac_addr_t)) != 0
        || ethernet_header->type != 0x8e88) {
        eapol.type = -1;
        return *this;
    }
    // Remove header
    uint8_t *buf = recv_buf.data() + 18 + sizeof(ethernet_header_t);
    #endif

    if (len - sizeof(ethernet_header_t) == 0) return *this;

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

EAPClient &EAPClient::send(const eapol_t &eapol) {
    std::string buf;
    buf.assign(ethernet_header.begin(), ethernet_header.end());
    buf += eapol.to_buf();

    #ifdef SYSTEM_LINUX
    int len = sendto(client_fd, buf.c_str(), buf.length(), MSG_NOSIGNAL,
                     (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    #elif SYSTEM_DARWIN
    int len = write(bpf_fd, buf.c_str(), buf.length());
    #endif
    return *this;
}

void EAPClient::set_timeout(int to_sec) {
    #ifdef SYSTEM_LINUX
    struct timeval timeout;
    timeout.tv_sec = to_sec;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
    #elif SYSTEM_DARWIN
    timeout.tv_sec = to_sec;
    #endif
}

}
