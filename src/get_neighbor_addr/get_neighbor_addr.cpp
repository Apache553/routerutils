

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

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

std::vector<std::string> split_string(const std::string &str, char sep) {
    std::vector<std::string> vec;
    size_t pos = 0;
    while (pos != std::string::npos) {
        size_t rpos = str.find(sep, pos);
        vec.push_back(str.substr(pos, rpos - pos));
        if (rpos + 1 < str.size() && rpos != std::string::npos)
            pos = rpos + 1;
        else
            pos = std::string::npos;
    }
    return vec;
}

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
    int err = inet_pton(AF_INET, str.substr(0, pos).c_str(), &ret.addr.inet);
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

bool parse_lladdr(uint8_t *bin, const std::string &str) {
    auto vec = split_string(str, ':');
    if (vec.size() != 6)
        return false;
    for (size_t i = 0; i < 6; ++i) {
        try {
            int tmp = std::stoi(vec[i], nullptr, 16);
            if (tmp < 0 || tmp > 255)
                return false;
            bin[i] = tmp;
        } catch (...) {
            return false;
        }
    }
    return true;
}

bool cidr_include(const cidr &addr1, const cidr &addr2) {
    if (addr1.family != addr2.family)
        return false;
    uint8_t mask = addr1.mask < addr2.mask ? addr1.mask : addr2.mask;
    if (memcmp(&addr1.addr, &addr2.addr, mask / 8) == 0) {
        if (mask % 8 == 0)
            return true;
        int offset = mask / 8;
        int bits = 8 - (mask % 8);
        if ((((const uint8_t *)(&addr1.addr))[offset] >> bits) ==
            (((const uint8_t *)(&addr2.addr))[offset] >> bits)) {
            return true;
        }
    }
    return false;
}

void show_help(char *exe) {
    std::cout << "Usage: " << exe
              << " [Family:4/6] [Interface] [LLAddr] [Prefix]\n";
    exit(0);
}

cidr make_cidr(int family, void *addr, uint8_t mask = 0xff) {
    cidr ret;
    ret.family = family;
    memcpy(&ret.addr, addr,
           family == AF_INET ? sizeof(in_addr) : sizeof(in6_addr));
    if (mask == 0xff)
        ret.mask = family == AF_INET ? 32 : 128;
    else
        ret.mask = mask;
    return ret;
}

bool filter_neigh_dst(const Neighbor &neigh) {
    bool ret = false;
    uint64_t l64 = 0;
    ret |= memcmp(&neigh.lladdr, &l64, 6 * sizeof(uint8_t)) == 0;
    ret |= cidr_include(make_cidr(neigh.family, (void *)&neigh.addr),
                        parse_cidr("224.0.0.0/4"));
    ret |= cidr_include(make_cidr(neigh.family, (void *)&neigh.addr),
                        parse_cidr("ff00::/8"));
    ret |= cidr_include(make_cidr(neigh.family, (void *)&neigh.addr),
                        parse_cidr("0000:0000::1/128"));
    ret |= cidr_include(make_cidr(neigh.family, (void *)&neigh.addr),
                        parse_cidr("127.0.0.1/32"));
    ret |= cidr_include(make_cidr(neigh.family, (void *)&neigh.addr),
                        parse_cidr("0.0.0.0/32"));
    ret |= cidr_include(make_cidr(neigh.family, (void *)&neigh.addr),
                        parse_cidr("::/128"));

    return ret;
}

int parse_attribute_callback(const struct nlattr *attr, void *data) {
    int type = mnl_attr_get_type(attr);
    Neighbor *neigh = static_cast<Neighbor *>(data);
    void *ptr;

    if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
        return MNL_CB_OK;

    switch (type) {
    case NDA_DST:
        ptr = mnl_attr_get_payload(attr);
        memcpy(&neigh->addr, ptr,
               neigh->family == AF_INET ? sizeof(in_addr) : sizeof(in6_addr));
        break;
    case NDA_LLADDR:
        ptr = mnl_attr_get_payload(attr);
        memcpy(&neigh->lladdr, ptr, sizeof(uint8_t) * 6);
        break;
    }
    return MNL_CB_OK;
}

int parse_callback(const struct nlmsghdr *nlh, void *data) {
    Neighbor neigh;

    ndmsg *ndm = static_cast<ndmsg *>(mnl_nlmsg_get_payload(nlh));

    neigh.family = ndm->ndm_family;
    neigh.ifindex = ndm->ndm_ifindex;
    neigh.status = ndm->ndm_state;
    neigh.is_proxy = ndm->ndm_flags & NTF_PROXY;
    neigh.is_router = ndm->ndm_flags & NTF_ROUTER;

    if (mnl_attr_parse(nlh, sizeof(*ndm), parse_attribute_callback, &neigh) <
        0) {
        std::cerr << "unexpected error when parsing netlink message\n";
        exit(1);
    };

    std::vector<Neighbor> *vec = static_cast<std::vector<Neighbor> *>(data);

    if (!filter_neigh_dst(neigh))
        vec->push_back(neigh);

    return MNL_CB_OK;
}

int main(int argc, char **argv) {
    int ifidx;
    Neighbor config;
    cidr prefix;
    memset(&config, 0xff, sizeof(config));
    memset(&prefix, 0xff, sizeof(prefix));

    std::vector<Neighbor> neighbors;

    switch (argc) {
    case 5:
        prefix = parse_cidr(argv[4]);
        if (prefix.family == -1)
            show_help(argv[0]);
    case 4:
        if (!parse_lladdr(config.lladdr, argv[3]))
            show_help(argv[0]);
    case 3:
        ifidx = if_nametoindex(argv[2]);
    case 2:
        if (std::string("4") == argv[1])
            config.family = AF_INET;
        else if (std::string("6") == argv[1])
            config.family = AF_INET6;
        else
            show_help(argv[0]);
    case 1:
        break;
    default:
        show_help(argv[0]);
    }

    // dump neighbors

    struct mnl_socket *nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ndmsg *ndm;
    int ret;
    unsigned int seq, portid;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);

    ndm = static_cast<ndmsg *>(
        mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg)));
    ndm->ndm_family = config.family == -1 ? AF_UNSPEC : config.family;

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        std::cerr << "mnl_socket_open failed.\n";
        exit(1);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        std::cerr << "mnl_socket_bind failed.\n";
        exit(1);
    }

    portid = mnl_socket_get_portid(nl);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        std::cerr << "mnl_socket_sendto failed.\n";
        exit(1);
    }

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, seq, portid, parse_callback, &neighbors);
        if (ret <= MNL_CB_STOP)
            break;
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }

    if (ret == -1) {
        std::cerr << "unexpected error\n";
        exit(1);
    }
    
    mnl_socket_close(nl);

    //     for (auto &i : neighbors) {
    //         char out[INET6_ADDRSTRLEN];
    //         inet_ntop(i.family, &i.addr, out, sizeof(out));
    //         std::cout << "ifidx: " << i.ifindex << "; addr: " << out
    //                   << "; lladdr: " << std::hex << (uint16_t)i.lladdr[0] <<
    //                   ":"
    //                   << (uint16_t)i.lladdr[1] << ":" <<
    //                   (uint16_t)i.lladdr[2]
    //                   << ":" << (uint16_t)i.lladdr[3] << ":"
    //                   << (uint16_t)i.lladdr[4] << ":" <<
    //                   (uint16_t)i.lladdr[5]
    //                   << std::dec << "\n";
    //     }

    // filter requested addr

    for (auto &i : neighbors) {
        char out[INET6_ADDRSTRLEN];
        inet_ntop(i.family, &i.addr, out, sizeof(out));
        switch (argc) {
        case 5:
            if (!cidr_include(prefix, make_cidr(i.family, &i.addr)))
                continue;
        case 4:
            if (memcmp(i.lladdr, config.lladdr, sizeof(uint8_t) * 6) != 0)
                continue;
        case 3:
            if (i.ifindex != ifidx)
                continue;
        case 2:
        case 1:
            break;
        }
        std::cout << out << "\n";
    }

    return 0;
}
