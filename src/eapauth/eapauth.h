#pragma once

#include "eapdef.h"
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <array>
#include "eaputils.h"

namespace sysuh3c {

class EAPAuth {
public:
    EAPAuth(const std::string &, const std::string &, const std::string &, eap_method);
    ~EAPAuth();

    void auth();
    void logoff();
    void set_promote_listener(const std::function<void(const std::string &)> &);
    void set_status_listener(const std::function<void(int statno)> &);

    std::string get_user_name() const;

private:
    void send_start();
    void send_logoff();
    void send_response_id(uint8_t packet_id);
    void send_response_md5(uint8_t packet_id, const std::vector<uint8_t> &md5data);
    void send_response_h3c(uint8_t packet_id);

    void eap_handler(const eapol_t &eapol_packet);

    bool has_sent_logoff;

    EAPClient eapclient;
    std::string user_name;
    std::string user_password;
    eap_method md5_method;

    std::function<void(const std::string &)> display_promote;
    std::function<void(int statno)> status_notify;
};

}
