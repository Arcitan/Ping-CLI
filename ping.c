/*
 *
 * A simple "ping" CLI application for Unix-based systems. Accepts a
 * hostname/IP address from the command line, then sends ICMP "echo requests"
 * in a loop to the target while receiving "echo reply" messages. Reports
 * loss and RTT times for each sent message.
 *
 * References:
 *      http://www.ping127001.com/pingpage.htm
 *
 */
#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Global constants */
#define MAXBUF          8192
#define MAXLINE         8192
#define PACKETSIZE      64
#define PAYLOADSIZE     (PACKETSIZE - sizeof(struct icmphdr))
#define DEFAULTPORT     0

/* Structs */
struct packet {
        struct icmphdr hdr;
        char payload[PAYLOADSIZE];
};

/* Global variables */
struct protoent *proto = NULL;

/* Function signatures */
static int open_socket(char *hostname);


/*
 * Requires:
 *   "hostname" points to a string representing either a valid host name or
 *   an IP address.
 *
 * Effects:
 *   Opens a raw socket connection to the server at <hostname> and
 *   returns a file descriptor ready for reading and writing.  Returns -1 and
 *   sets errno on a Unix error.  Returns -2 on a DNS (getaddrinfo) error.
 */
static int
open_socket(char *hostname)
{
        struct addrinfo *ai;
        int sd, err;

        // Retrieve information about the "ICMP" protocol
        if ((proto = getprotobyname("ICMP")) == NULL) {
                fprintf(stderr, "error: failed to retrieve ICMP protocol\n");
                return (-1);
        }

        // Set "sd" to a newly created raw socket
        if ((sd = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
                fprintf(stderr, "error: failed to create socket\n");
                return (-1);
        };

        // Use getaddrinfo() to get the server's IP address
        if ((err = getaddrinfo(hostname, NULL, NULL, &ai)) != 0) {
                fprintf(stderr, "error: getaddrinfo failed: %s\n",
                    gai_strerror(err));
                return (-2);
        }

        return (sd);
}

/*
 * Requires:
 *   argv[1] is a string representing either a host name or a valid IP address.
 *
 * Effects:
 *   Continually sends ICMP "echo requests" in an infinite loop with a
 *   periodic delay between each request. Upon receiving an "echo reply"
 *   message back from the server, it reports the loss and RTT times for each
 *   message received. It continues to do this until the program is terminated.
 */
int
main(int argc, char **argv)
{
        int sd;
        char *host;

        // Verify usage
        if (argc != 2) {
                fprintf(stderr, "usage: %s <host>\n", argv[0]);
                exit(1);
        }

        // Set up a raw socket to the host
        host = argv[1];
        sd = open_socket(host);
        if (sd == -1) {
                fprintf(stderr,
                    "open_socket unix error: %s\n",
                    strerror(errno));
        } else if (sd == -2) {
                fprintf(stderr, "open_socket dns error\n");
        }

        return (0);
}
