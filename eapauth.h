#pragma once

#include "eapdef.h"
#include <netpacket/packet.h>
#include <functional>
#include <iostream>
#include <stdexcept>

class EAPAuth {
    public:
        EAPAuth(const std::string&, const std::string&, const std::string&);
        ~EAPAuth();

        void auth() const;
        void logoff();
        void redirect_promote(const std::function<void(const std::string&)>&);
        void set_status_changed_listener(const std::function<void(int statno)>&);

        std::string get_user_name() const;

    private:
        void send_start() const;
        void send_logoff() const;
        void send_response_id(uint8_t packet_id) const;
        void send_response_md5(uint8_t packet_id, const std::string& md5data) const;
        void send_response_h3c(uint8_t packet_id) const;

        bool eap_handler(const std::string& eap_packet) const;

        std::string mac_addr;
        int client_fd;
        bool has_sent_logoff;
        std::string ethernet_header;

        std::string iface;
        std::string user_name;
        std::string user_password;

        struct sockaddr_ll sock_addr;

        std::function<void(const std::string&)> display_promote;
        std::function<void(int statno)> status_notify;
};

class EAPAuthException : public std::runtime_error {
    public: 
        explicit EAPAuthException(const std::string&);
};
