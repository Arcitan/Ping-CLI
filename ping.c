/*
 * A simple "ping" CLI application for Unix-based systems. Accepts a
 * hostname/IP address from the command line, then sends ICMP "echo requests"
 * in a loop to the target while receiving "echo reply" messages. Reports
 * loss and RTT times for each sent message.
 *
 * References:
 *   (1) http://www.ping127001.com/pingpage.htm
 *   (2) https://www.cs.utah.edu/~swalton/listings/sockets/programs/part4/chap18/myping.c
 *   (3) https://www.tenouk.com/Module43a.html
 *   (4) https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
 *   (5) https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
 *   (6) https://www.geeksforgeeks.org/internet-control-message-protocol-icmp/
 *   (7) https://www.johndcook.com/blog/standard_deviation/
 *
 */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Macros */
#define MAX(x, y)  ((x) > (y) ? (x) : (y))
#define MIN(x, y)  ((x) > (y) ? (y) : (x))

/* Global constants */
#define PACKETSIZE      64
#define PAYLOADSIZE     (PACKETSIZE - sizeof(struct icmphdr))
#define SLEEPRATE       1
#define TTLVAL          64

/* Structs */
struct packet {
        struct icmphdr hdr;
        char payload[PAYLOADSIZE];
};

/* Global variables */
struct protoent *proto = NULL;  /* Pointer to protocol info */
struct sockaddr_in serveraddr;  /* The destination IP info */
long double rtt_min = UINT_MAX; /* Minimum packet RTT */
long double rtt_max = 0;        /* Maximum packet RTT */
long double rtt_tot = 0;        /* Total packet RTT */
long double rtt_std = 0;        /* Standard deviation of RTT */
unsigned int nsent = 0;         /* # of packets sent */
unsigned int nreceived = 0;     /* # of packets received */
int pid = -1;                   /* Process ID of this process */
int sd;                         /* Socket file descriptor */
char hostname[NI_MAXHOST];      /* Host name of the destination */
char ip[INET_ADDRSTRLEN];       /* IP of the destination */
bool pingflag = 1;              /* Flag for the infinite ping loop */

/* Function signatures */
static unsigned short checksum(void *b, int len);

static int open_socket();

static void ping(const char *hostparam);

static void sigint_handler(int signum);

static void show_stats();


/*
 * Define a custom SIGINT handler.
 *
 * Requires:
 *   "signum" must be the SIGINT signal.
 *
 * Effects:
 *   Catches the SIGCHLD signal from the kernel and simply toggles the ping
 *   loop flag off.
 *
 *   Implementation inspired by Reference (6).
 */
static void
sigint_handler(int signum)
{
        assert(signum == SIGINT);

        /* Stop the ping loop */
        pingflag = 0;
}


/*
 * Requires:
 *   None.
 *
 * Effects:
 *   Prints out statistics about the packets we pinged.
 *
 *   Implementation inspired by Reference (1).
 */
static void
show_stats()
{
        /* Print out statistics. */
        putchar('\n');
        fflush(stdout);
        printf("\n----%s ping statistics----\n", hostname);
        printf("%d packets transmitted, ", nsent);
        printf("%d packets received, ", nreceived);
        if (nreceived > nsent) {
                printf("...huh?\n");
        } else {
                printf("%d%% packet loss\n",
                    (int) (((nsent - nreceived) * 100) /
                        nsent));
        }
        printf("rtt min/avg/max/stdev = %.3Lf/%.3Lf/%.3Lf/%.3Lf ms\n",
            rtt_min,
            rtt_tot / nreceived,
            rtt_max,
            rtt_std);
        fflush(stdout);
}


/*
 * Requires:
 *   None.
 *
 * Effects:
 *   Computes the 1s complement checksum for IP family headers. Taken from
 *   Reference (2).
 *
 */
unsigned short
checksum(void *b, int len)
{
        unsigned short *buf = b;
        unsigned int sum = 0;
        unsigned short result;

        for (sum = 0; len > 1; len -= 2)
                sum += *buf++;
        if (len == 1)
                sum += *(unsigned char *) buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        result = ~sum;
        return result;
}


/*
 * Requires:
 *   "hostparam" must be a valid NUL-terminated host name string.
 *
 * Effects:
 *   Continuously pings the destination server with ICMP packets and receives
 *   the "echo reply" packets sent back.
 */
static void
ping(const char *hostparam)
{
        struct sockaddr_in clientaddr;
        struct packet pckt;
        struct timespec ts, te;
        long double pckt_time, rtt;
        long double m = 0, s = 0, tmp_m;
        unsigned int clientlen = sizeof(clientaddr);
        unsigned int i, k = 1;
        int bytes_rec;
        bool was_sent = 1;

        /* Display opening message */
        printf("PING %s (%s) %lu(%d) bytes of data.\n", hostparam, ip,
            PAYLOADSIZE,
            PACKETSIZE);

        /*
         * Continue sending pings until told to stop
         */
        while (pingflag) {
                /* Create the ICMP packet */
                bzero(&pckt, sizeof(pckt));
                pckt.hdr.type = ICMP_ECHO;
                pckt.hdr.un.echo.id = pid;
                for (i = 0; i < sizeof(pckt.payload) - 1; i++)
                        pckt.payload[i] = i + '0';
                pckt.payload[i] = 0;
                pckt.hdr.un.echo.sequence = nsent++;
                pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

                sleep(SLEEPRATE);

                /* Send the packet */
                clock_gettime(CLOCK_MONOTONIC, &ts);
                if (sendto(sd, &pckt, sizeof(pckt), 0,
                    (struct sockaddr *) &serveraddr,
                    sizeof(serveraddr)) <= 0) {
                        perror("sendto");
                        // Mark packet as not sent
                        was_sent = 0;
                }

                /* Receive the returning packet */
                if ((bytes_rec = recvfrom(sd, &pckt, sizeof(pckt), 0,
                    (struct sockaddr *) &clientaddr, &clientlen)) < 0) {
                        /*
                         * Ignore any signal interrupt errors, since that's
                         * part of normal usage (user will CTRL+C)
                         */
                        if (!(errno = EINTR)) {
                                perror("ping: recvfrom");
                        }

                        // Try next packet since we failed to receive this one
                        continue;
                }

                /* Compute elapsed time between sending and receiving */
                clock_gettime(CLOCK_MONOTONIC, &te);
                pckt_time = ((double) (te.tv_nsec - ts.tv_nsec)) /
                    1000000.0;
                rtt = (te.tv_sec - ts.tv_sec) * 1000.0 + pckt_time;

                /* Keep track of statistics */
                rtt_min = MIN(rtt_min, rtt);
                rtt_max = MAX(rtt_min, rtt);
                rtt_tot += rtt;

                /*
                 * Compute st. dev. of a stream using Welford's method (see
                 * Reference (7))
                 */
                tmp_m = m;
                m += ((rtt - tmp_m) / k);
                s += ((rtt - tmp_m) * (rtt - m));
                k++;
                rtt_std = sqrt(s / (k - 2));

                /* Inspect the received packet and print out results */
                if (was_sent) {
                        // Verify packet consistency
                        if (pckt.hdr.code != ICMP_ECHOREPLY) {
                                fprintf(stderr,
                                    "packet received with ICMP type %d and code "
                                    "%d\n", pckt.hdr.type, pckt.hdr.code);
                                continue;
                        }

                        // Print results
                        printf(
                            "%d bytes from %s (%s): icmp_seq=%d ttl=%d rtt=%Lf "
                            "ms\n", bytes_rec, hostname, ip, nsent, TTLVAL,
                            rtt);

                        nreceived++;
                }
        }

}


/*
 * Requires:
 *   "hostname" points to a string representing either a valid host name or
 *   an IP address.
 *
 * Effects:
 *   Opens a raw socket connection to the server at <hostname> and
 *   returns a file descriptor ready for reading and writing.  Returns -1 and
 *   sets errno on a Unix error.
 */
static int
open_socket()
{
        /* Retrieve information about the "ICMP" protocol */
        if ((proto = getprotobyname("ICMP")) == NULL) {
                fprintf(stderr, "failed to retrieve ICMP protocol\n");
                return (-1);
        }

        /* Set "sd" to a newly created raw socket */
        if ((sd = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
                fprintf(stderr, "failed to create socket\n");
                return (-1);
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
        struct addrinfo *ai;
        struct sigaction action;
        const int ttlval = TTLVAL;
        unsigned int addrlen;
        int err;
        char *host;

        /* Verify usage */
        if (argc != 2) {
                fprintf(stderr, "usage: %s <host>\n", argv[0]);
                exit(1);
        }

        /* Store the process ID (we'll use it in the packet) */
        pid = getpid();

        /* Install sigint_handler() as the handler for SIGINT (ctrl-c). */
        action.sa_handler = sigint_handler;
        action.sa_flags = SA_RESTART;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, NULL) < 0)
                perror("sigaction error");

        /* Use getaddrinfo() to get the server's IP address. */
        host = argv[1];
        if ((err = getaddrinfo(host, NULL, NULL, &ai)) != 0) {
                printf("getaddrinfo: %s\n", gai_strerror(err));
        }

        /*
         * Set the address of serveraddr to be server's IP address and port.
         * Be careful to ensure that the IP address and port are in network
         * byte order.
         */
        addrlen = sizeof(serveraddr);
        bzero(&serveraddr, addrlen); /* Port defaults to 0 */
        serveraddr.sin_family = ai->ai_family;
        serveraddr.sin_addr = ((struct sockaddr_in *) ai->ai_addr)->sin_addr;

        /* Get the **actual** host name and IP address of the host */
        if ((err = getnameinfo((struct sockaddr *) &serveraddr, addrlen,
            hostname, NI_MAXHOST, NULL, 0, 0)) < 0) {
                printf("getnameinfo: %s\n", gai_strerror(err));
        }
        if (!inet_ntop(AF_INET, &serveraddr.sin_addr, ip,
            INET_ADDRSTRLEN)) {
                perror("inet_ntop error");
        }

        /* Open a raw socket to the destination */
        if ((sd = open_socket()) == -1) {
                perror("open_socket() unix error");
        }

        /*
         * Set the TTL value for the socket. If a packet remains out in the
         * network for longer than the set TTL value, it will be discarded.
         */
        if (setsockopt(sd, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) != 0)
                perror("setsockopt: failed to set TTL value");

        /* Continuously ping the host */
        ping(host);

        /* Print statistics once we're done */
        show_stats();

        /* Cleanup and exit */
        close(sd);
        freeaddrinfo(ai);

        return (0);
}
