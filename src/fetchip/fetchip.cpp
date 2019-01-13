
#include <iostream>
#include <cstring>
#include <cerrno>

#include<sys/ioctl.h>
#include<sys/types.h>
#include<sys/socket.h>

#include<net/if.h>
#include<arpa/inet.h>

#include<unistd.h>

int main(int argc, char** argv) {
    if( argc == 1 ) {
        std::cerr << "Usage: " << argv[0] << " <interface name>\n";
        return -1;
    }
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if( sockfd < 0 ) {
        std::cerr << "socket() failed: " << std::strerror(errno) << '\n';
        return -1;
    }

    ifreq request;
    memset(&request, 0, sizeof(request));
    if( strlen(argv[1]) + 1 > IFNAMSIZ ) {
        std::cerr << "Interface name length exceeded!\n";
        close(sockfd);
        return -1;
    }
    strcpy(request.ifr_name, argv[1]);
    if( ioctl(sockfd, SIOCGIFADDR, &request) < 0) {
        std::cerr << "ioctl() failed: " << std::strerror(errno) << '\n';
        close(sockfd);
        return -1;
    }
    
    char ipaddr[INET_ADDRSTRLEN];
    if( inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(&request.ifr_addr)->sin_addr.s_addr, ipaddr, sizeof(char)*INET_ADDRSTRLEN) == nullptr) {
        std::cerr << "inet_ntop() failed: " << std::strerror(errno) << '\n';
        close(sockfd);
        return -1;
    }

    std::cout << ipaddr << std::endl;

    close(sockfd);
    return 0;
}
