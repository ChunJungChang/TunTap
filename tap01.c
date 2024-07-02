/*
 * cc -g tap01.c
 * #sudo ./a.out tap01
 * #sudo ip tuntap add dev tap01 mode tap -> tap_alloc()
 * #sudo ip addr add 203.0.113.1/24 dev tap01 -> set_dev_ip()
 * sudo ip link set up dev tap01 -> set_dev_up()
 * ip link show tap01
 * ping 203.0.113.2 -I tap01
 */

/*
 * cc -g tap01.c
 * sudo ./a.out tap01
 * #sudo ip tuntap add dev tap01 mode tap -> tap_alloc()
 * #sudo ip link set up dev tap01 -> set_dev_up()
 * ip link show tap01
 * ping 8.8.8.8 -I tap01
 *
 * ffffffffffffe24e2972a08e08060001080006040001e24e2972a08e0ace43d400000000000008080808
 *
 * https://hpd.gasmi.net/
 * e2:4e:29:72:a0:8e → Broadcast ARP Who has 8.8.8.8? Tell 10.206.67.212 
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include <net/if.h> // ifreq
#include <linux/if_tun.h> // IFF_TAP, IFF_NO_PI
#include <linux/if_arp.h>
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

int tap_alloc(const char *dev)
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
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (strlen(dev) > 0)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
       close(fd);
       return err;
    }

    return fd;
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

int main(int argc, char** argv)
{
    int tap_fd = 0;
    char buffer[BUFFLEN];
    char buffer2[2*BUFFLEN + 1];

    if (argc != 2)
        return 1;
    const char* device_name = argv[1];
    if (strlen(device_name) + 1 > IFNAMSIZ)
        return 1;

    // Request a TAP device:
	tap_fd = tap_alloc(device_name);
	if (tap_fd < 0) {
        perror("Allocating interface failed");
        exit(1);
    }

    //set_dev_ip(device_name, "203.0.113.1", "255.255.255.0");
    set_dev_up(device_name);

    while (1) {
        // Read a frame:
        ssize_t count = read(tap_fd, buffer, BUFFLEN);
        if (count < 0)
            return 1;

        // Dump frame:
        hex(buffer, buffer2, count);
        fprintf(stderr, "%s\n", buffer2);
    }

    if (tap_fd)
        close(tap_fd);

    return 0;
}
