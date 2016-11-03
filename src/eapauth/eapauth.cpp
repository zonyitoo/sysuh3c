#include "eapdef.h"
#include "eapauth.h"
#include "eaputils.h"
#include "md5.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <cstring>
#include <iostream>
#include <cstdio>
#include <stdexcept>
#include <stdarg.h>
#ifdef WITH_SHOWMESSAGE
#   include <iconv.h>
#endif
#include <iterator>

namespace sysuh3c {

EAPAuth::EAPAuth(const std::string &user_name,
                 const std::string &password, const std::string &iface,
                 eap_method method)
    : eapclient(iface),
      user_name(user_name), user_password(password), md5_method(method),
    display_promote([this] (const std::string &os) {
    std::cout << os << std::endl;
}),
status_notify([this] (int8_t statno) {
    std::cout << "statno=" << statno << std::endl;
})
{

}

EAPAuth::~EAPAuth() {
    send_logoff();
}

void EAPAuth::send_start() {
    eapol_t eapol_start;
    eapol_start.vers = EAPOL_VERSION;
    eapol_start.type = EAPOL_START;
    eapol_start.eapol_len = eapol_start.get_len();

    try {
        eapclient << eapol_start;
    }
    catch (const EAPAuthException &exp) {
        throw EAPAuthException("send_start error");
    }
}

void EAPAuth::send_logoff() {
    eapol_t eapol_logoff;
    eapol_logoff.vers = EAPOL_VERSION;
    eapol_logoff.type = EAPOL_LOGOFF;
    eapol_logoff.eapol_len = eapol_logoff.get_len();

    try {
        eapclient << eapol_logoff;
    }
    catch (const EAPAuthException &exp) {
        throw EAPAuthException("send_logoff error");
    }
}

void EAPAuth::send_response_id(uint8_t packet_id) {
    eapol_t eapol_id;
    eapol_id.vers = EAPOL_VERSION;
    eapol_id.type = EAPOL_EAPPACKET;
    eapol_id.eap.reset(new eap_t);
    eapol_id.eap->code = EAP_RESPONSE;
    eapol_id.eap->id = packet_id;
    eapol_id.eap->reqtype = EAP_TYPE_ID;
    eapol_id.eap->data.assign(VERSION_INFO.begin(), VERSION_INFO.end());
    eapol_id.eap->data.insert(eapol_id.eap->data.end(), user_name.begin(), user_name.end());
    eapol_id.eap->eap_len = eapol_id.eap->get_len();
    eapol_id.eapol_len = eapol_id.get_len();

    try {
        eapclient << eapol_id;
    }
    catch (const EAPAuthException &exp) {
        throw EAPAuthException("send_response_id error");
    }
}

void EAPAuth::send_response_md5(uint8_t packet_id, const std::vector<uint8_t> &md5data) {
    std::array<uint8_t, 16> chap;
    std::string pwd(user_password);
    std::vector<uint8_t> chapbuf; 
    size_t chapbuflen = 1 + pwd.length() + 16;

    switch (md5_method) {
        case EAP_METHOD_XOR: // xor(password, md5data)
            if (pwd.length() < 16)
                pwd.append(16 - pwd.length(), '\0');
            for (size_t i = 0; i < chap.size(); ++ i)
                chap[i] = pwd[i] ^ md5data[i];
            break;
        case EAP_METHOD_MD5: // MD5(id + password + md5data)
        default:
            chapbuf.push_back(packet_id);
            chapbuf.insert(chapbuf.end(), pwd.begin(), pwd.end());
            chapbuf.insert(chapbuf.end(), md5data.begin(), md5data.end());

            MD5_CTX context;
            MD5_Init(&context);
            MD5_Update(&context, &chapbuf[0], chapbuflen);
            MD5_Final(&chap[0], &context);
            break;
    }

    eapol_t eapol_md5;
    eapol_md5.vers = EAPOL_VERSION;
    eapol_md5.type = EAPOL_EAPPACKET;
    eapol_md5.eap.reset(new eap_t);
    eapol_md5.eap->code = EAP_RESPONSE;
    eapol_md5.eap->id = packet_id;
    eapol_md5.eap->reqtype = EAP_TYPE_MD5;
    eapol_md5.eap->data.push_back(16);
    eapol_md5.eap->data.insert(eapol_md5.eap->data.end(), chap.begin(), chap.end());
    eapol_md5.eap->data.insert(eapol_md5.eap->data.end(), user_name.begin(), user_name.end());
    eapol_md5.eap->eap_len = eapol_md5.eap->get_len();
    eapol_md5.eapol_len = eapol_md5.get_len();
    try {
        eapclient << eapol_md5;
    }
    catch (const EAPAuthException &exp) {
        throw EAPAuthException("send_response_md5 error");
    }
}

void EAPAuth::send_response_h3c(uint8_t packet_id) {
    std::vector<uint8_t> resp;
    resp.push_back(user_password.length());
    resp.insert(resp.end(), user_password.begin(), user_password.end());
    resp.insert(resp.end(), user_name.begin(), user_name.end());

    eapol_t eapol_h3c;
    eapol_h3c.vers = EAPOL_VERSION;
    eapol_h3c.type = EAPOL_EAPPACKET;
    eapol_h3c.eap.reset(new eap_t);
    eapol_h3c.eap->code = EAP_RESPONSE;
    eapol_h3c.eap->id = packet_id;
    eapol_h3c.eap->reqtype = EAP_TYPE_H3C;
    eapol_h3c.eap->data.push_back(user_password.length());
    eapol_h3c.eap->data.insert(eapol_h3c.eap->data.end(), user_password.begin(), user_password.end());
    eapol_h3c.eap->data.insert(eapol_h3c.eap->data.end(), user_name.begin(), user_name.end());
    eapol_h3c.eap->eap_len = eapol_h3c.eap->get_len();
    eapol_h3c.eapol_len = eapol_h3c.get_len();

    try {
        eapclient << eapol_h3c;
    }
    catch (const EAPAuthException &exp) {
        throw EAPAuthException("send_response_h3c error");
    }
}

void EAPAuth::eap_handler(const eapol_t &eapol_packet) {
    if (eapol_packet.type != EAPOL_EAPPACKET) {
        //status_notify(EAPAUTH_UNKNOWN_PACKET_TYPE);
        return;
    }
    switch (eapol_packet.eap->code) {
    case EAP_SUCCESS:
        status_notify(EAPAUTH_EAP_SUCCESS);
        eapclient.set_timeout(30);
        break;
    case EAP_FAILURE:
        status_notify(EAPAUTH_EAP_FAILURE);
        eapclient.set_timeout(5);
        throw EAPAuthFailed();
    case EAP_RESPONSE:
        status_notify(EAPAUTH_EAP_RESPONSE);
        break;
    case EAP_REQUEST:
    {
        switch (eapol_packet.eap->reqtype) {
        case EAP_TYPE_ID:
            status_notify(EAPAUTH_AUTH_ID);
            send_response_id(eapol_packet.eap->id);
            break;
        case EAP_TYPE_H3C:
            status_notify(EAPAUTH_AUTH_H3C);
            send_response_h3c(eapol_packet.eap->id);
            break;
        case EAP_TYPE_MD5:
            status_notify(EAPAUTH_AUTH_MD5);
            send_response_md5(eapol_packet.eap->id, eapol_packet.eap->data);
            break;
        default:
            status_notify(EAPAUTH_UNKNOWN_REQUEST_TYPE);
        }
    }
    break;
    case 10:
#ifdef WITH_SHOWMESSAGE
        {
            iconv_t cd = iconv_open("UTF-8", "GBK");
            if (cd == (iconv_t) - 1) {
                perror("iconv_open");
                break;
            }
            size_t outleft = eapol_packet.eap->data.size() * 2;
            char *buf = new char[outleft];
            size_t inleft = eapol_packet.eap->data.size() + 1;
            char *p_in = const_cast<char *>((const char *) eapol_packet.eap->data.data()) + 2;

            char *p_out = buf;
            while (inleft != 0) {
                size_t ret = iconv(cd, &p_in, &inleft, &p_out, &outleft);
                if (ret == (size_t) - 1) {
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
#endif
        break;
    default:
        status_notify(EAPAUTH_UNKNOWN_EAP_CODE);
    }
}

void EAPAuth::auth() {
    send_start();
    status_notify(EAPAUTH_AUTH_START);
    while (true) {
        eapol_t packet;
        eapclient >> packet;
        try {
            eap_handler(packet);
        }
        catch (EAPAuthFailed &exp) {
            throw exp;
        }
        catch (EAPAuthException &exp) {
            throw exp;
        }
    }
}

void EAPAuth::logoff() {
    eapclient.set_timeout(5);
    send_logoff();
}

void EAPAuth::set_promote_listener(const std::function<void (const std::string &)> &func) {
    display_promote = func;
}

void EAPAuth::set_status_listener(const std::function<void(int)> &func) {
    status_notify = func;
}

std::string EAPAuth::get_user_name() const {
    return user_name;
}

}
