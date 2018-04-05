#include <stdio.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
 
int main(int argc, char **argv) {
    struct ifreq ifr;
    struct sockaddr_ll sll;
    struct packet_mreq mreq;

    printf("ETH_P_ALL             = %#06x\n", htons(ETH_P_ALL));
    printf("SIOCGIFINDEX          = %#06x\n", SIOCGIFINDEX);
    printf("SOL_PACKET            = %#06x\n", SOL_PACKET);
    printf("PACKET_ADD_MEMBERSHIP = %#06x\n", PACKET_ADD_MEMBERSHIP);
    printf("PACKET_DROP_MEMBERSHIP = %#06x\n", PACKET_DROP_MEMBERSHIP);
    printf("PACKET_MR_PROMISC     = %#06x\n", PACKET_MR_PROMISC);
    printf("IFREQ_SIZE            = %#06zx\n", sizeof(ifr));
    printf("IFINDEX_SIZE          = %#06zx\n", sizeof(ifr.ifr_ifindex));
    printf("SOCKADDR_LL_SIZE      = %#06zx\n", sizeof(sll));
    printf("PACKET_MREQ_SIZE      = %#06zx\n", sizeof(mreq));
 
    return 0;
}
