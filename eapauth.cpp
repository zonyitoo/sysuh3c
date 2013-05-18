#include "eapdef.h"
#include "eapauth.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <cstring>
#include <iostream>
#include <cstdio>
#include <stdexcept>
#include <stdarg.h>
#include <iconv.h>

EAPAuth::EAPAuth(const std::string& user_name, 
        const std::string& password, const std::string& iface)
    :  client_fd(-1),
    iface(iface), user_name(user_name), user_password(password),
    display_promote([this] (const std::string& os) { std::cout << os << std::endl; }),
    status_notify([this] (int8_t statno) { std::cout << "statno=" << statno << std::endl; })
{
    if ((client_fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))) < 0) {
        perror("socket");
        abort();
    }

    //setsockopt(client_fd, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.length());
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));

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

    if (ioctl(client_fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        abort();
    }

    char mac_addr_buf[6] = {0};
    for (size_t i = 0; i < 6; ++ i)
        mac_addr_buf[i] = ifr.ifr_hwaddr.sa_data[i];
    mac_addr.assign(mac_addr_buf, sizeof(mac_addr_buf));

    if (ioctl(client_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        abort();
    }

    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sll_family = AF_PACKET;
    sock_addr.sll_ifindex = ifr.ifr_ifindex;
    sock_addr.sll_protocol = htons(ETHERTYPE_PAE);

    if (bind(client_fd, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) == -1) {
        perror("bind");
        abort();
    }

    ethernet_header = get_ethernet_header(mac_addr, 
            std::string(PAE_GROUP_ADDR, sizeof(PAE_GROUP_ADDR) - 1), ETHERTYPE_PAE);
}

EAPAuth::~EAPAuth() {
    send_logoff();
    shutdown(client_fd, SHUT_RDWR);
}

void EAPAuth::send_start() const {
    static std::string eap_start_packet = ethernet_header + get_EAPOL(EAPOL_START);
    int len = sendto(client_fd, eap_start_packet.c_str(), eap_start_packet.size(), MSG_NOSIGNAL,
            (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_start error");
}

void EAPAuth::send_logoff() const {
    static std::string eap_logoff_packet = ethernet_header + get_EAPOL(EAPOL_LOGOFF);
    int len = sendto(client_fd, eap_logoff_packet.c_str(), eap_logoff_packet.size(), MSG_NOSIGNAL,
            (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_logoff error");
}

void EAPAuth::send_response_id(uint8_t packet_id) const {
    std::string eap_response_id_packet =
        ethernet_header + 
        get_EAPOL(EAPOL_EAPPACKET, 
                get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_ID, 
                    std::string(VERSION_INFO, sizeof(VERSION_INFO) - 1) + user_name));
    int len = sendto(client_fd, eap_response_id_packet.c_str(), eap_response_id_packet.size(),
            MSG_NOSIGNAL, (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_response_id error");
}

void EAPAuth::send_response_md5(uint8_t packet_id, const std::string& md5data) const {
    char chap[16] = {0};
    std::string pwd(user_password);
    if (pwd.length() < 16)
        pwd.append(16 - pwd.length(), '\0');
    for (size_t i = 0; i < 16; ++ i) {
        chap[i] = pwd[i] ^ md5data[i];
    }
    std::string resp;
    resp.append(1, 16);
    resp.append(chap, sizeof(chap));
    resp.append(user_name);

    std::string eap_md5_packet = ethernet_header + 
        get_EAPOL(EAPOL_EAPPACKET, 
                get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_MD5, resp));
    int len = sendto(client_fd, eap_md5_packet.c_str(), eap_md5_packet.length(), MSG_NOSIGNAL,
            (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_response_md5 error");
}

void EAPAuth::send_response_h3c(uint8_t packet_id) const {
    std::string resp;
    resp.append(1, (char) user_password.length());
    resp.append(user_password);
    resp.append(user_name);

    std::string eap_h3c_packet = 
        ethernet_header + get_EAPOL(EAPOL_EAPPACKET, 
                get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_H3C, resp));

    int len = sendto(client_fd, eap_h3c_packet.c_str(), eap_h3c_packet.length(), MSG_NOSIGNAL,
            (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_response_h3c error");
}

bool EAPAuth::eap_handler(const std::string& eap_packet) const {
    eapol_t eapol_packet;
    eapol_packet.vers = eap_packet[0];
    eapol_packet.type = eap_packet[1];
    eapol_packet.eapol_len = ntohs(*((uint16_t *) &eap_packet[2]));
    
    if (eapol_packet.type != EAPOL_EAPPACKET) {
        status_notify(EAPAUTH_UNKNOWN_PACKET_TYPE);
        return true;
    }

    eapol_packet.eap.code = eap_packet[4];
    eapol_packet.eap.id = eap_packet[5];
    
    eapol_packet.eap.eap_len = ntohs(*(uint16_t *) &eap_packet[6]);

    switch (eapol_packet.eap.code) {
        case EAP_SUCCESS:
            {
                status_notify(EAPAUTH_EAP_SUCCESS);
                struct timeval timeout;
                timeout.tv_sec = 30;
                timeout.tv_usec = 0;
                setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
                break;
            }
        case EAP_FAILURE:
            {
                status_notify(EAPAUTH_EAP_FAILURE);
                struct timeval timeout;
                timeout.tv_sec = 5;
                timeout.tv_usec = 0;
                setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
            }
            return false;
            break;
        case EAP_RESPONSE:
            status_notify(EAPAUTH_EAP_RESPONSE);
            break;
        case EAP_REQUEST:
            eapol_packet.eap.reqtype = eap_packet[8];
            eapol_packet.eap.datalen = eap_packet[9];
            eapol_packet.eap.data = eap_packet.substr(10, eapol_packet.eap.eap_len - 6);
            switch (eapol_packet.eap.reqtype) {
                case EAP_TYPE_ID:
                    status_notify(EAPAUTH_AUTH_ID);
                    send_response_id(eapol_packet.eap.id);
                    break;
                case EAP_TYPE_H3C:
                    status_notify(EAPAUTH_AUTH_H3C);
                    send_response_h3c(eapol_packet.eap.id);
                    break;
                case EAP_TYPE_MD5:
                    status_notify(EAPAUTH_AUTH_MD5);
                    send_response_md5(eapol_packet.eap.id, eapol_packet.eap.data);
                    break;
                default:
                    status_notify(EAPAUTH_UNKNOWN_REQUEST_TYPE);
            }
            break;
        case 10:
            {
                iconv_t cd = iconv_open("UTF-8", "GBK");
                if (cd == (iconv_t) -1) {
                    perror("iconv_open");
                    break;
                }
                size_t outleft = (eap_packet.length() + 1 - 12) * 2;
                char *buf = new char[outleft];
                size_t inleft = eap_packet.length() + 1 - 12;
                char *p_in = const_cast<char *>(eap_packet.c_str()) + 12;

                char *p_out = buf;
                while (inleft != 0) {
                    size_t ret = iconv(cd, &p_in, &inleft, &p_out, &outleft);
                    if (ret == (size_t) -1) {
                        *p_out = *p_in;
                        p_out ++;
                        p_in ++;
                        inleft --;
                        outleft --;
                    }
                }

                std::string convstr(buf);
                convstr.append(p_in);
                display_promote(std::move(convstr));

                delete [] buf;
                break;
            }
        default:
            status_notify(EAPAUTH_UNKNOWN_EAP_CODE);
    }
    return true;
}

void EAPAuth::auth() const {
    char buf[1600] = {0};
    send_start();
    status_notify(EAPAUTH_AUTH_START);
    while (true) {
        socklen_t sock_addr_len = sizeof(sock_addr);
        int len = recvfrom(client_fd, buf, sizeof(buf), 0,
                           (struct sockaddr *) &sock_addr, &sock_addr_len);
        if (len <= 0) throw EAPAuthException("Socket recv error");
        if (!eap_handler(std::string(buf + 14, len - 14))) break;
    }
}

void EAPAuth::logoff() {
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
    send_logoff();
}

void EAPAuth::redirect_promote(const std::function<void (const std::string &)> &func) {
    display_promote = func;
}

void EAPAuth::set_status_changed_listener(const std::function<void(int)> &func) {
    status_notify = func;
}

std::string EAPAuth::get_user_name() const {
    return user_name;
}

EAPAuthException::EAPAuthException(const std::string& what_arg)
    : std::runtime_error(what_arg) {}
