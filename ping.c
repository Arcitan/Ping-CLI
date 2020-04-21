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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>


int
main(int argc, char *argv[])
{
        (void) argc;
        (void) argv;
        return (0);
}