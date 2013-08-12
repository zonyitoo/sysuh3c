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
#include <iterator>

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

    mac_addr_t mac_addr;
    for (size_t i = 0; i < mac_addr.size(); ++ i)
        mac_addr[i] = ifr.ifr_hwaddr.sa_data[i];

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

    ethernet_header = get_ethernet_header(mac_addr, PAE_GROUP_ADDR, ETHERTYPE_PAE);
}

EAPAuth::~EAPAuth() {
    send_logoff();
    shutdown(client_fd, SHUT_RDWR);
}

void EAPAuth::send_start() const {
    static std::vector<uint8_t> eap_start_packet(ethernet_header);
    get_EAPOL(eap_start_packet, EAPOL_START);
    int len = sendto(client_fd, eap_start_packet.data(), eap_start_packet.size(), MSG_NOSIGNAL,
            (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_start error");
}

void EAPAuth::send_logoff() const {
    static std::vector<uint8_t> eap_logoff_packet(ethernet_header);
    get_EAPOL(eap_logoff_packet, EAPOL_LOGOFF);
    int len = sendto(client_fd, eap_logoff_packet.data(), eap_logoff_packet.size(), MSG_NOSIGNAL,
            (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_logoff error");
}

void EAPAuth::send_response_id(uint8_t packet_id) const {
    std::vector<uint8_t> eap_response_id_packet(ethernet_header);
    std::vector<uint8_t> eap_payload;
    eap_payload.assign(VERSION_INFO.begin(), VERSION_INFO.end());
    eap_payload.insert(eap_payload.end(), user_name.begin(), user_name.end());
    get_EAPOL(eap_response_id_packet, EAPOL_EAPPACKET, get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_ID, eap_payload));
    int len = sendto(client_fd, eap_response_id_packet.data(), eap_response_id_packet.size(),
            MSG_NOSIGNAL, (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_response_id error");
}

void EAPAuth::send_response_md5(uint8_t packet_id, const std::vector<uint8_t>& md5data) const {
    std::array<uint8_t, 16> chap;
    std::string pwd(user_password);
    if (pwd.length() < 16)
        pwd.append(16 - pwd.length(), '\0');
    for (size_t i = 0; i < chap.size(); ++ i) {
        chap[i] = pwd[i] ^ md5data[i];
    }
    std::vector<uint8_t> resp;
    resp.push_back(16);
    resp.insert(resp.end(), chap.begin(), chap.end());
    resp.insert(resp.end(), user_name.begin(), user_name.end());

    std::vector<uint8_t> eap_md5_packet(ethernet_header);
    get_EAPOL(eap_md5_packet, EAPOL_EAPPACKET, 
            get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_MD5, resp));
    int len = sendto(client_fd, eap_md5_packet.data(), eap_md5_packet.size(), MSG_NOSIGNAL,
            (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_response_md5 error");
}

void EAPAuth::send_response_h3c(uint8_t packet_id) const {
    std::vector<uint8_t> resp;
    resp.push_back(user_password.length());
    resp.insert(resp.end(), user_password.begin(), user_password.end());
    resp.insert(resp.end(), user_name.begin(), user_name.end());

    std::vector<uint8_t> eap_h3c_packet(ethernet_header);
    get_EAPOL(eap_h3c_packet, EAPOL_EAPPACKET, 
            get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_H3C, resp));

    int len = sendto(client_fd, eap_h3c_packet.data(), eap_h3c_packet.size(), MSG_NOSIGNAL,
            (struct sockaddr *) &sock_addr, sizeof(sock_addr));
    if (len < 0)
        throw EAPAuthException("send_response_h3c error");
}

bool EAPAuth::eap_handler(const std::vector<uint8_t>& v_eap_packet) const {
    eapol_t eapol_packet;
    const uint8_t * eap_packet = v_eap_packet.data();
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
            {
                eapol_packet.eap.reqtype = eap_packet[8];
                eapol_packet.eap.datalen = eap_packet[9];
                std::vector<uint8_t>::const_iterator itr = v_eap_packet.begin();
                std::advance(itr, 10);
                std::vector<uint8_t>::const_iterator eitr = itr;
                eapol_packet.eap.data.assign(itr, v_eap_packet.end());
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
            }
            break;
        case 10:
            {
                iconv_t cd = iconv_open("UTF-8", "GBK");
                if (cd == (iconv_t) -1) {
                    perror("iconv_open");
                    break;
                }
                size_t outleft = (v_eap_packet.size() + 1 - 12) * 2;
                char *buf = new char[outleft];
                size_t inleft = v_eap_packet.size() + 1 - 12;
                char *p_in = const_cast<char *>((const char *) v_eap_packet.data()) + 12;

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
            }
            break;
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
        std::vector<uint8_t> packet;
        for (int i = 14; i < len; ++ i)
            packet.push_back(buf[i]);
        if (!eap_handler(packet)) break;
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
