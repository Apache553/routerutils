#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <csignal>
#include <stdexcept>

#include <arpa/inet.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

std::string if_name;
std::string exec_file;
std::vector<char*> exec_argv;

int addr_handler(const nlmsghdr* nlh, void* data);
std::vector<std::pair<std::string, int>> get_interface_list();

int main(int argc, char** argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <interface> <command>\n", argv[0]);
		return -1;
	}
	
	if_name = argv[1];
	exec_file = argv[2];
	// build argv used by execvp
	for (int i = 2; i < argc; ++i) {
		exec_argv.push_back(argv[i]);
	}
	exec_argv.push_back(nullptr);

	signal(SIGCHLD, SIG_IGN); // avoid zombie process

	mnl_socket* nlsock;
	char buffer[MNL_SOCKET_BUFFER_SIZE];

	nlsock = mnl_socket_open(NETLINK_ROUTE);
	if (nlsock == nullptr) {
		perror("mnl_socket_open");
		return 1;
	}

	// listen ipv4/v6 address new/delete event
	if (mnl_socket_bind(nlsock, RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return 1;
	}

	int ret = mnl_socket_recvfrom(nlsock, buffer, sizeof(buffer));
	while (true) {
		ret = mnl_cb_run(buffer, ret, 0, 0, addr_handler, NULL);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(nlsock, buffer, sizeof(buffer));

	}
	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nlsock);

	return 0;
}

/*
    utility function to get newest interface name to index mapping
*/
std::vector<std::pair<std::string, int>> get_interface_list() {
	std::vector<std::pair<std::string, int>> result;
	mnl_socket* sock = mnl_socket_open(NETLINK_ROUTE);
	char buffer[MNL_SOCKET_BUFFER_SIZE];
	unsigned int seq, portid;

	if (sock == nullptr) {
		perror("get_interface_list()::mnl_socket_open");
		throw std::runtime_error("get_interface_list failure.");
	}
	if (mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("get_interface_list()::mnl_socket_bind");
		throw std::runtime_error("get_interface_list failure.");
	}

	struct nlmsghdr* nl_hdr;
	struct rtgenmsg* rt_msg;
	nl_hdr = mnl_nlmsg_put_header(buffer);
	nl_hdr->nlmsg_type = RTM_GETLINK;
	nl_hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;;
	nl_hdr->nlmsg_seq = seq = time(nullptr);
	rt_msg = (rtgenmsg*)mnl_nlmsg_put_extra_header(nl_hdr, sizeof(struct rtgenmsg));
	rt_msg->rtgen_family = AF_PACKET;

	portid = mnl_socket_get_portid(sock);

	if (mnl_socket_sendto(sock, nl_hdr, nl_hdr->nlmsg_len) < 0) {
		perror("get_interface_list()::mnl_socket_sendto");
		throw std::runtime_error("get_interface_list failure.");
	}

	auto data_callback = [](const nlmsghdr* hdr, void* data) -> int {
		std::vector<std::pair<std::string, int>>& result = *(std::vector<std::pair<std::string, int>>*)data;
		ifinfomsg* ifm = (ifinfomsg*)mnl_nlmsg_get_payload(hdr);
		std::pair<std::string, int> entry;
		auto attr_callback = [](const nlattr* attr, void* data)->int {
			std::pair<std::string, int>& entry = *(std::pair<std::string, int>*)data;
			int type = mnl_attr_get_type(attr);
			if (mnl_attr_type_valid(attr, IFLA_MAX) < 0) {
				return MNL_CB_OK;
			}
			if (type == IFLA_IFNAME) {
				if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
					perror("mnl_attr_validate(attr, MNL_TYPE_STRING)");
					return MNL_CB_ERROR;
				}
				entry.first = mnl_attr_get_str(attr);
			}
			return MNL_CB_OK;
		};
		entry.second = ifm->ifi_index;
		if (mnl_attr_parse(hdr, sizeof(ifinfomsg), attr_callback, &entry) == MNL_CB_ERROR) {
			throw std::runtime_error("parse interface name failure.");
		}
		result.push_back(entry);
		return MNL_CB_OK;
	};

	int ret;
	ret = mnl_socket_recvfrom(sock, buffer, sizeof(buffer));
	while (ret > 0) {
		ret = mnl_cb_run(buffer, ret, seq, portid, data_callback, &result);
		if (ret <= MNL_CB_STOP) {
			break;
		}
		ret = mnl_socket_recvfrom(sock, buffer, sizeof(buffer));
	}
	if (ret == -1) {
		perror("get_interface_list()");
		throw std::runtime_error("receive failure.");
	}
	mnl_socket_close(sock);
	return result;
}

void do_exec(const std::string& optype, const std::string& family, const std::string& value) {
	pid_t cpid = fork();
	if (cpid == 0) {
		setenv("OPTYPE", optype.c_str(), 1);
		setenv("FAMILY", family.c_str(), 1);
		setenv("VALUE", value.c_str(), 1);
		execvp(exec_file.c_str(), exec_argv.data());
		perror("execvp");
		exit(1);
	}
}

inline const char* family_to_str(int family) {
	switch (family) {
	case AF_INET:
		return "AF_INET";
	case AF_INET6:
		return "AF_INET6";
	default:
		return "UNKNOWN";
	}
}

int addr_handler(const nlmsghdr* nlh, void* data) {
	ifaddrmsg* msg = (ifaddrmsg*)mnl_nlmsg_get_payload(nlh);
	auto if_list = get_interface_list();
	int if_index = -1;

	for (const auto& entry : if_list) {
		if (entry.first == if_name) {
			if_index = entry.second;
		}
	}
	if (if_index == -1)return MNL_CB_OK;
	if (msg->ifa_index != if_index)return MNL_CB_OK;
	
	auto parse_addr = [](const nlattr* attr, void* data)->int {
		int type = mnl_attr_get_type(attr);
		std::string& addr = *(std::string*)data;
		if (mnl_attr_type_valid(attr, IFA_MAX) < 0) {
			return MNL_CB_OK;
		}
		if (type == IFA_ADDRESS) {
			if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
				perror("mnl_attr_validate(attr, MNL_TYPE_BINARY)");
				return MNL_CB_ERROR;
			}
			void* addr_b = mnl_attr_get_payload(attr);
			char outbuf[INET6_ADDRSTRLEN];
			if (inet_ntop(addr.empty() ? AF_INET : AF_INET6, addr_b, outbuf, sizeof(outbuf)) == nullptr) {
				perror("inet_ntop");
				return MNL_CB_ERROR;
			}
			addr = outbuf;
		}
		return MNL_CB_OK;
	};

	std::string addr;
	if (msg->ifa_family == AF_INET6)addr = "AF_INET6";
	if (mnl_attr_parse(nlh, sizeof(ifaddrmsg), parse_addr, &addr) == MNL_CB_ERROR) {
		throw std::runtime_error("parse interface address failure.");
	}

	// call given commands
	switch (nlh->nlmsg_type) {
	case RTM_NEWADDR:
		do_exec("NEW", family_to_str(msg->ifa_family), addr);
		break;
	case RTM_DELADDR:
		do_exec("DEL", family_to_str(msg->ifa_family), addr);
		break;
	}

	return MNL_CB_OK;
}
