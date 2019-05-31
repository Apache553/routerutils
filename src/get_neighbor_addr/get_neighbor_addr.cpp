

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include <arpa/inet.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

struct Neighbor {
    int ifindex;
    int family;
    uint8_t lladdr[6];
    union {
        in_addr inet;
        in6_addr inet6;
    } addr;
    uint16_t status;
    bool is_proxy;
    bool is_router;
};

struct cidr {
    int family;
    union {
        in6_addr inet6;
        in_addr inet;
    } addr;
    uint8_t mask;
};

cidr parse_cidr(const std::string &str) {
    cidr ret;
    int mask;
    size_t pos = str.rfind('/');
    if (pos != std::string::npos && pos != str.length() - 1) {
        try {
            mask = std::stoi(str.substr(pos + 1));
        } catch (...) {
            ret.family = -1;
            return ret;
        }
    } else {
        ret.family = -1;
        return ret;
    }
    // try parse it as ipv4 addr
    int err = inet_pton(AF_INET, str.substr(0, pos).c_str(), &ret.addr.inet4);
    if (err > 0) {
        if (mask > 32 || mask < 0) {
            ret.family = -1;
            return ret;
        }
        ret.family = AF_INET;
        ret.mask = mask;
        return ret;
    }
    // else try ipv6
    err = inet_pton(AF_INET6, str.substr(0, pos).c_str(), &ret.addr.inet6);
    if (err > 0) {
        if (mask > 128 || mask < 0) {
            ret.family = -1;
            return ret;
        }
        ret.family = AF_INET6;
        ret.mask = mask;
        return ret;
    }
    ret.family = -1;
    return ret;
}

bool cidr_include(const cidr &addr1, const cidr &addr2) {}
