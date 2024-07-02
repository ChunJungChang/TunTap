/*
 * cc -g tun01.c
 * sudo ./a.out tun01
 * #sudo ip tuntap add dev tun01 mode tun -> tun_alloc()
 * #sudo ip addr add 203.0.113.1/24 dev tun01 -> set_dev_ip()
 * #sudo ip link set up dev tun01 -> set_dev_up()
 * ip link show tun01
 * ping 203.0.113.2 -I tun01
 */

/*
 * cc -g tun01.c
 * sudo ./a.out tun01
 * #sudo ip tuntap add dev tun01 mode tun -> tun_alloc()
 * #sudo ip link set up dev tun01 -> set_dev_up()
 * ip link show tun01
 * ping 8.8.8.8 -I tun01
 *
 * IPv4: src=10.206.67.212 dst=8.8.8.8 proto=1(icmp) ttl=64
 *  HEX: 45000054fbe440004001e0120ace43d4080808080800b008d3150006ed9f9b65000000002503080000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637
 *
 *  10.206.67.212 → 8.8.8.8 ICMP Echo (ping) request
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include <netinet/in.h> // IPPROTO_*
#include <net/if.h> // ifreq
#include <linux/if_tun.h> // IFF_TUN, IFF_NO_PI
#include <arpa/inet.h> //inet_pton

#include <sys/ioctl.h>

#define BUFFLEN (4 * 1024)

const char HEX[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f',
};

void hex(char* source, char* dest, ssize_t count)
{
    for (ssize_t i = 0; i < count; ++i) {
        unsigned char data = source[i];
        dest[2 * i] = HEX[data >> 4];
        dest[2 * i + 1] = HEX[data & 15];
    }
    dest[2 * count] = '\0';
}

int has_ports(int protocol)
{
    switch(protocol) {
    case IPPROTO_UDP:
    case IPPROTO_UDPLITE:
    case IPPROTO_TCP:
        return 1;
    default:
        return 0;
    }
}

void dump_ports(int protocol, int count, const char* buffer)
{
    if (!has_ports(protocol))
        return;
    if (count < 4)
        return;
    uint16_t source_port;
    uint16_t dest_port;
    memcpy(&source_port, buffer, 2);
    source_port = htons(source_port);
    memcpy(&dest_port, buffer + 2, 2);
    dest_port = htons(dest_port);
    fprintf(stderr, " sport=%u, dport=%d\n", (unsigned) source_port, (unsigned) dest_port);
}

void dump_packet_ipv4(int count, char* buffer)
{
    if (count < 20) {
        fprintf(stderr, "IPv4 packet too short\n");
        return;
    }

    char buffer2[2*BUFFLEN + 1];
    hex(buffer, buffer2, count);

    int protocol = (unsigned char) buffer[9];
    struct protoent* protocol_entry = getprotobynumber(protocol);

    unsigned ttl = (unsigned char) buffer[8];

    fprintf(stderr, "IPv4: src=%u.%u.%u.%u dst=%u.%u.%u.%u proto=%u(%s) ttl=%u\n",
        (unsigned char) buffer[12], (unsigned char) buffer[13], (unsigned char) buffer[14], (unsigned char) buffer[15],
        (unsigned char) buffer[16], (unsigned char) buffer[17], (unsigned char) buffer[18], (unsigned char) buffer[19],
        (unsigned) protocol,
        protocol_entry == NULL ? "?" : protocol_entry->p_name, ttl
    );
    dump_ports(protocol, count - 20, buffer + 20);
    fprintf(stderr, " HEX: %s\n", buffer2);
}

void dump_packet_ipv6(int count, char* buffer)
{
    if (count < 40) {
        fprintf(stderr, "IPv6 packet too short\n");
        return;
    }

    char buffer2[2*BUFFLEN + 1];
    hex(buffer, buffer2, count);

    int protocol = (unsigned char) buffer[6];
    struct protoent* protocol_entry = getprotobynumber(protocol);

    char source_address[33];
    char destination_address[33];

    hex(buffer + 8, source_address, 16);
    hex(buffer + 24, destination_address, 16);

    int hop_limit = (unsigned char) buffer[7];

    fprintf(stderr, "IPv6: src=%s dst=%s proto=%u(%s) hop_limit=%i\n",
        source_address, destination_address,
        (unsigned) protocol,
        protocol_entry == NULL ? "?" : protocol_entry->p_name,
        hop_limit);
    dump_ports(protocol, count - 40, buffer + 40);
    fprintf(stderr, " HEX: %s\n", buffer2);
}

void dump_packet(int count, char* buffer)
{
    unsigned char version = ((unsigned char) buffer[0]) >> 4;
    if (version == 4) {
        dump_packet_ipv4(count, buffer);
    } else if (version == 6) {
        dump_packet_ipv6(count, buffer); 
    } else {
        fprintf(stderr, "Unknown packet version\n");
    }
}

int set_dev_ip(const char *dev, const char *ipaddr, const char *netmask)
{
    struct ifreq ifr;
    int err;
    
    /*
     * ioctl needs one fd as an input.
     * Request kernel to give me an unused fd. 
     */
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    
    // Set the interface name.
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    ifr.ifr_addr.sa_family = AF_INET;
    
    /*
     * Set IP address
     * The structure of ifr.ifr_addr.sa_data is "struct sockaddr"
     * struct sockaddr
     * {
     *     unsigned short    sa_family;
     *     char              sa_data[14];
     * }
     * This is why + 2 is used.
     */
    if ((err = inet_pton(AF_INET, ipaddr, ifr.ifr_addr.sa_data + 2)) != 1) {
        perror("Error IP address.");
        close(fd);
        return err;
    }
    if ((err = ioctl(fd, SIOCSIFADDR, &ifr)) < 0) {
        perror( "IP: ioctl(SIOCSIFADDR)" );
        close( fd );
        return err;
    }
    
    // Set netmask
    if ((err = inet_pton(AF_INET, netmask, ifr.ifr_addr.sa_data + 2)) != 1) {
        perror("Error IP address.");
        close(fd);
        return err;
    }
    if ((err = ioctl( fd, SIOCSIFNETMASK, &ifr)) < 0) {
        perror("Netmask: ioctl(SIOCSIFNETMASK)");
        close(fd);
        return err;
    }
    
    close(fd);
    
    return 1;
}

int set_dev_up(const char *dev)
{
    struct ifreq ifr;
    int err;
    
    /*
     * ioctl needs one fd as an input.
     * Request kernel to give me an unused fd. 
     */
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    
    // Set the interface name.
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    ifr.ifr_addr.sa_family = AF_INET;
    
    /*
     * Enable the interface
     * Get the interface flag first and add IFF_UP | IFF_RUNNING.
     */
    if ((err = ioctl(fd, SIOCGIFFLAGS, &ifr)) < 0) {
        perror("ioctl(SIOCGIFFLAGS)");
        close(fd);
        return err;
    }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if ((err = ioctl(fd, SIOCSIFFLAGS, &ifr)) < 0) {
        perror("ioctl(SIOCSIFFLAGS)");
        close(fd);
        return err;
    }
    
    close(fd);
    
    return 1;
}

int tun_alloc(const char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        perror( "Opening /dev/net/tun" );
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (strlen(dev) > 0)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
       close(fd);
       return err;
    }

    return fd;
}

int main(int argc, char** argv)
{
	int tun_fd = 0;
    char buffer[BUFFLEN];

    if (argc != 2)
        return 1;
    const char* device_name = argv[1];
    if (strlen(device_name) + 1 > IFNAMSIZ)
        return 1;

    // Request a TUN device:
	tun_fd = tun_alloc(device_name);
	if (tun_fd < 0) {
        perror("Allocating interface failed");
        exit(1);
    }

    //set_dev_ip(device_name, "203.0.113.1", "255.255.255.0");
    set_dev_up(device_name);

	while (1) {
        // Read an IP packet:
        ssize_t count = read(tun_fd, buffer, BUFFLEN);
        if (count < 0)
            return 1;
		dump_packet(count, buffer);
    }

    if (tun_fd)
	    close(tun_fd);

	return 0;
}
