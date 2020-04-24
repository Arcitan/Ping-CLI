# Ping-CLI 

## What is it?

A minimal CLI "ping" application. Accepts a hostname or an IPv4 address as its
 argument, then
 sends ICMP "echo requests" in a loop to the target while receiving "echo
  reply" messages. By default, it reports loss and RTT times for each sent
   message.

This application was written entirely in C for Unix-based systems. This
 application was developed on a Windows 10 machine, and tested on the Ubuntu
  Windows subsystem. 
 Because this implementation employs raw sockets, it requires root privileges to
  execute. 

## Installation 

```
$ cd this/project/root
$ make 
```

## Usage 
``` 
./ping   [-c count] [-h] [-i interval] [-s payloadsize]
         [-t ttl] [-w deadline] [-W timeout] destination
```
To execute this application with default behavior, simply call 
```
$ sudo ./ping <destination> 
```

By default, this application will continuously ping the destination host and
 listen for replies. You can terminate the program any time by
  typing `Ctrl-C` into the terminal window. This application takes a
   number of optional arguments, and they are listed in detail below.  


## Options 
The following is lifted from `man ping(8)`, with minor adjustments in
 accordance with the behavior of this version of **ping**. 
*  `-c <count>`:  Stop after sending _count_ ECHO_REQUEST packets.
*  `-h`: Dispays the usage message. 
*  `-i <interval>`: Wait interval seconds between sending each packet. 
The default is to wait for one second between each packet normally. 
*  `-s <payloadsize>`: Specifies the number of data bytes to be sent.
 The default is 56, which translates into 64 ICMP data bytes when combined with
  the 8 bytes of ICMP header data.
*  `-t <ttl>`: Set the IP time-to-live.
*  `-w <deadline>`: Specify a timeout, in seconds, before **ping** exits
 regardless 
of how many packets have been sent or received.
*  `-W <timeout>`: Time to wait for a response, in seconds. By default, this
 is 1 second. 
   
If ping does not receive any reply packets at all it will exit with code 1. 
If a packet count and deadline are both specified, and fewer than count packets
 are received by the time the deadline has arrived, it will also exit with 
 code 1. On other error it exits with code 2. Otherwise it exits with code 0. 
 This makes it possible to use the exit code to see if a host is alive or not.

 

