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
#define MAXPACKETSIZE 4096      /* Max packet size */
#define TIMEOUT         5       /* Timeout for packet return */
#define SLEEPRATE       1
#define TTLVAL          55

/* Global variables */
struct protoent *proto = NULL;  /* Pointer to protocol info */
struct sockaddr_in serveraddr;  /* The destination IP info */
long double rtt_min = UINT_MAX; /* Minimum packet RTT */
long double rtt_max = 0;        /* Maximum packet RTT */
long double rtt_tot = 0;        /* Total packet RTT */
long double rtt_std = 0;        /* Standard deviation of RTT */
long double m = 0;              /* Intermediate value in Welford's method */
long double s = 0;              /* Intermediate value in Welford's method */
unsigned int iphdrsize;         /* Size of the IP header in received packets */
unsigned int insize;            /* Size of each incoming packet */
unsigned int nsent = 0;         /* # of packets sent */
unsigned int nreceived = 0;     /* # of packets received */
unsigned int outsize = 64;      /* Size of each outgoing packet (default=64) */
unsigned int payloadsize;       /* Payload size of each packet */
extern int errno;               /* Written to by UNIX functions */
int pid = -1;                   /* Process ID of this process */
int sd;                         /* Socket file descriptor */
char hostname[NI_MAXHOST];      /* Host name of the destination */
char ip[INET_ADDRSTRLEN];       /* IP of the destination */
char inpacket[MAXPACKETSIZE];   /* Incoming packet buffer */
char outpacket[MAXPACKETSIZE];  /* Outgoing packet buffer */
bool pingflag = 1;              /* Flag for the infinite ping loop */

/* Function signatures */
static unsigned short checksum(void *b, int len);

static long double compute_rtt();

static int open_socket();

static int ping();

static char *pr_type(const int t);

static int receive();

static void sigint_handler(int signum);

static void show_stats();

static void tv_sub(struct timeval *out, struct timeval *in);

static void update_std(long double rtt);

static int verify_packet(const unsigned int recvsize);


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
        printf("rtt min/avg/max/std = %.3Lf/%.3Lf/%.3Lf/%.3Lf ms\n",
            rtt_min,
            rtt_tot / nreceived,
            rtt_max,
            rtt_std);
        fflush(stdout);
}


/*
 * Requires:
 *   "len" must be the size of the buffer pointed to by "b".
 *
 * Effects:
 *   Computes the 1s complement checksum for IP family headers.
 *
 *   Implementation pulled from Reference (2).
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
 *   "rtt" must be a valid long double.
 *
 * Effects:
 *   Computes the online standard deviation of all the aggregate "rtt"'s
 *   using Welford's method.
 *
 *   Implementation inspired by Reference (7).
 */
static void
update_std(long double rtt)
{
        long double m_old = m;
        long double var;

        if (nreceived == 1) {
                m = rtt;
        } else {
                m += ((rtt - m_old) / nreceived);
                s += ((rtt - m_old) / (rtt - m));
        }

        var = nreceived > 1 ? (s / (nreceived - 1)) : 0;
        rtt_std = sqrt(var);
}


/*
 * Requires:
 *   None.
 *
 * Effects:
 *   Computes the round-trip delay time of a packet. Returns the round-trip
 *   delay time (rtt) on success, and -1 on any failures.
 */
static long double
compute_rtt()
{
        struct icmp *pckt;
        struct timeval *ts, te;
        long double rtt;

        // Get receive time (now)
        if (gettimeofday(&te, NULL) < 0) {
                perror("receive: gettimeofday");
                return (-1);
        }
        // Get send time (stored in packet)
        pckt = (struct icmp *) (inpacket + iphdrsize);
        ts = (struct timeval *) pckt->icmp_data;
        tv_sub(&te, ts);
        rtt = (te.tv_sec * 1000) + ((long double) te.tv_usec / 1000);

        /* Keep track of statistics */
        rtt_min = MIN(rtt_min, rtt);
        rtt_max = MAX(rtt_max, rtt);
        rtt_tot += rtt;

        /*
         * Compute standard deviation of a stream using Welford's method (see
         * Reference (7))
         */
        update_std(rtt);

        return (rtt);
}


/*
 * Requires:
 *   "out" and "in" must both be pointers to valid struct timevals.
 *
 * Effects:
 *   Computes "out" - "in", and stores the difference in time in "out".
 *
 * Implementation taken from Reference (1).
 */
static void
tv_sub(struct timeval *out, struct timeval *in)
{
        if ((out->tv_usec -= in->tv_usec) < 0) {
                out->tv_sec--;
                out->tv_usec += 1000000;
        }
        out->tv_sec -= in->tv_sec;
}


/*
 * Requires:
 *   "t" is an ICMP header type.
 *
 * Effects:
 *   Converts an ICMP type into a human-readable format.
 *
 *
 * Implementation taken from Reference (1).
 */
static char *
pr_type(const int t)
{
        static char *ttab[] = {
            "Echo Reply",
            "ICMP 1",
            "ICMP 2",
            "Dest Unreachable",
            "Source Quench",
            "Redirect",
            "ICMP 6",
            "ICMP 7",
            "Echo",
            "ICMP 9",
            "ICMP 10",
            "Time Exceeded",
            "Parameter Problem",
            "Timestamp",
            "Timestamp Reply",
            "Info Request",
            "Info Reply"
        };

        if (t < 0 || t > 16)
                return ("OUT-OF-RANGE");

        return (ttab[t]);
}


/*
 * Requires:
 *   "hostparam" must be a valid NUL-terminated host name string.
 *
 * Effects:
 *   Continuously pings the destination server with ICMP packets and receives
 *   the "echo reply" packets sent back. Returns 0 on success and -1 if
 *   sending was unsuccessful.
 */
static int
ping()
{
        struct icmp *pckt;

        /* Wait between each packet */
        sleep(SLEEPRATE);

        /* Create the packet and fill in all the fields */
        pckt = (struct icmp *) outpacket;       // store in global buffer
        bzero(pckt, sizeof(outpacket));         // fields default to 0
        pckt->icmp_type = ICMP_ECHO;
        pckt->icmp_seq = ++nsent;               // label w/ packet #
        pckt->icmp_id = pid;                    // label w/ sender PID
        // store send time as the payload
        if (gettimeofday((struct timeval *) pckt->icmp_data, NULL) < 0) {
                perror("ping: gettimeofday");
                return (-1);
        }
        // compute ICMP checksum
        pckt->icmp_cksum = checksum(pckt, outsize);

        /* Send the packet */
        if (sendto(sd, outpacket, outsize, 0, (struct sockaddr *)
            &serveraddr, sizeof(serveraddr)) < 0) {
                perror("ping: sendto");
                nsent--;
                return (-1);
        }

        return (0);
}


/*
 * Requires:
 *   None.
 *
 * Effects:
 *   Receives an incoming ICMP "echo reply" packet back from the destination
 *   server. Computes some statistics about the packet and prints out
 *   information about receiving that packet. Returns 0 on success and -1 on
 *   any failure to receive a proper packet.
 */
static int
receive()
{
        struct icmp *pckt;
        socklen_t serverlen;
        long double rtt;
        int recvsize;
        serverlen = sizeof(serveraddr);

        /* Block until a packet is received */
        if ((recvsize = recvfrom(sd, inpacket, sizeof(inpacket), 0,
            (struct sockaddr *) &serveraddr, &serverlen)) < 0) {
                // Ignore SIGINT interrupts, since that's expected behavior
                if (errno != EINTR) {
                        // Check for timeout (EAGAIN is same as EWOULDBLOCK)
                        if (errno == EAGAIN) {
                                perror("recvfrom timed out\n");
                                return (-1);
                        }
                        // Catch all other errors
                        perror("error in packet receive");
                        return (-1);
                }
        }
        // Check for timeout with partially-received packet
        if (errno == EAGAIN) {
                perror("recvfrom timed out\n");
                return (-1);
        }

        /* Verify packet integrity */
        if (verify_packet(recvsize) < 0) {
                fprintf(stderr, "verify_packet error\n");
                return (-1);
        }

        /* Count this packet as received */
        nreceived++;

        /* Compute elapsed time between sending and receiving */
        if ((rtt = compute_rtt()) < 0) {
                fprintf(stderr, "compute_rtt error\n");
                return (-1);
        }

        /* Print out this packet's stats */
        pckt = (struct icmp *) (inpacket + iphdrsize);
        printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3Lf ms\n",
            insize, hostname, ip, pckt->icmp_seq, TTLVAL, rtt);

        return (0);
}


/*
 * Requires:
 *   "recvsize" must be the size of the packet received by recvfrom().
 *
 * Effects:
 *   Verifies the integrity of the received packet. Expects it to be an ICMP
 *   "echo reply" packet. Returns -1 on any error or malformed packet.
 *
 *   Packet integrity checking inspired by Reference (1).
 */
static int
verify_packet(const unsigned int recvsize)
{
        struct ip *hdr;
        struct icmp *pckt;

        /* Get header and header size */
        hdr = (struct ip *) inpacket;
        // ip_hl is # of DWORDS (32 bits), so convert to # of bytes (8 bits)
        iphdrsize = hdr->ip_hl << 2;
        /* Get the actual packet */
        pckt = (struct icmp *) (inpacket + iphdrsize);
        insize = recvsize - iphdrsize;

        /* Verify packet size */
        if (insize < iphdrsize + ICMP_MINLEN) {
                fprintf(stderr, "packet too short (%d bytes) from %s\n",
                    recvsize, hostname);
                return (-1);
        }

        /* Verify packet type */
        if (pckt->icmp_type != ICMP_ECHOREPLY) {
                fprintf(stderr, "type error: %d bytes from %s: icmp_type=%d "
                                "(%s) icmp_code=%d\n",
                    recvsize, hostname,
                    pckt->icmp_type, pr_type(pckt->icmp_type),
                    pckt->icmp_code);
                return (-1);
        }

        /* Verify packet origin */
        if (pckt->icmp_id != pid) {
                fprintf(stderr, "wrong packet id: (%d)\n", pckt->icmp_id);
                return (-1);
        }

        return (0);
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
        struct timeval tv;
        int ttlval = TTLVAL;

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

        /*
         * Set the TTL value for the socket. If a packet remains out in the
         * network for longer than the set TTL value, it will be discarded.
         */
        if (setsockopt(sd, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) != 0) {
                perror("setsockopt: failed to set TTL value");
        }

        /*
         * Set the timeout value for receive operations. If a receive
         * operation blocks for longer than the specified timeout, it will
         * return with a partial count or set "errno" to EAGAIN/EWOULDBLOCK
         * if no data is received.
         */
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
        if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
                perror("setsockopt: failed to set timeout");
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
        unsigned int addrlen;
        int err;
        char *host;

        /* Verify usage */
        if (argc != 2) {
                fprintf(stderr, "usage: %s <hostname/IPv4 addr>\n", argv[0]);
                exit(1);
        }


        /* TODO: Parse argv params */
        payloadsize = outsize - sizeof(struct icmphdr);

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

        /* Continuously ping the host */
        printf("PING %s (%s) %d(%d) bytes of data\n", host, ip, payloadsize,
            outsize);
        while (pingflag) {
                if (ping() != 0) {
                        fprintf(stderr, "ping failed to send packet %d\n",
                            nsent);
                        continue;
                }
                if (receive() != 0) {
                        fprintf(stderr, "receive error\n");
                        continue;
                }
        }

        /* Print statistics once we're done */
        show_stats();

        /*
         * Cleanup and exit. Normally we would error-check these, but since
         * the program is terminating anyway we can opt not to.
         */
        freeaddrinfo(ai);
        close(sd);

        return (0);
}
