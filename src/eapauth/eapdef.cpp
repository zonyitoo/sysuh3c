/*
 * =====================================================================================
 *
 *       Filename:  eapdef.cpp
 *
 *    Description:  eap struct and constants
 *
 *        Version:  1.0
 *        Created:  2013年08月18日 12时42分06秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Elton Chung
 *   Organization:  SYSU
 *
 * =====================================================================================
 */

#include "eapdef.h"

namespace sysuh3c {

std::string eap_t::to_buf() const {
    std::string result;
    result.append(1, code);
    result.append(1, id);
    uint16_t n = htons(eap_len);
    result.append((char *)(&n), sizeof(n));
    if (eap_len > 4) {
        result.append(1, reqtype);
        result.insert(result.end(), data.begin(), data.end());
    }
    return std::move(result);
}

uint16_t eap_t::get_len() const {
    if (code == EAP_SUCCESS || code == EAP_FAILURE)
        return sizeof(code) + sizeof(id) + sizeof(eap_len);
    return sizeof(code) + sizeof(id) + sizeof(eap_len) + sizeof(reqtype) + data.size();
}

std::string eapol_t::to_buf() const {
    std::string result;
    result.append(1, vers);
    result.append(1, type);
    uint16_t len = htons(eapol_len);
    result.append((char *)(&len), sizeof(len));
    if (eap.get() != nullptr)
        result += eap->to_buf();
    return std::move(result);
}

uint16_t eapol_t::get_len() const {
    if (eap.get() != nullptr)
        return eap->get_len();
    return 0;
}

}
