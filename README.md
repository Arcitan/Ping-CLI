# Ping-CLI 

## What is it?

A minimal CLI "ping" application for Linux-based systems. Accepts a hostname
 or an IPv4
 address as its
 argument, then
 sends ICMP "echo requests" in a loop to the target while receiving "echo
  reply" messages. By default, it reports loss and RTT times for each sent
   message.

This application was written entirely in C for Linux-based systems, developed
 on a Windows 10 machine, and tested on the Ubuntu
  Windows subsystem. Because this implementation depends on the `netinet
  ` libraries, it will not work on any machine that does not have these
   libraries, even if it's Unix-based. As of now, this means that this
    application will not work on MacOS; it will only work on Linux. 


## Installation 

```
$ cd this/project/root
$ make 
```

## Usage 
``` 
$ ./ping   [-c count] [-h] [-i interval] [-s payloadsize]
         [-t ttl] [-w deadline] [-W timeout] destination
```
 Because this implementation employs raw sockets, it requires root privileges to
  execute. 
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

## Discussion 
 
 Overall, I really enjoyed making this! This was my first time building a
  complete Linux-based CLI application completely from the ground-up. Though I
   came in with knowledge of exceptional control flow, sockets/networking
   , and basic error-handling, a lot of the other stuff necessary for this
    project I picked up along the way. For example, I had no
clue how to actually parse optional arguments on the command line, and I also
 didn't know how to set a timeout on a socket or properly set up an ICMP
  packet. Much of my time was spent reading documentation and man pages, as
   well as scouring StackOverflow for prior examples. However, I'm proud of
    what I was able to cobble together in the short amount of time that I had. 
Though this
   implementation is more robust than either of the minimal **ping** 
examples (References (2) and (6)), there are still areas I'd like to revisit. 

For example, I believe the actual Unix **ping** implementation uses at least
 two threads: one for sending, and the other for receiving. In doing so, it
  can continuously send out
   more
   packets even though it is waiting (a blocking action) for a packet to come
    in. Because of time contraints, and the non-trivial task of
     book-keeping the synchronization and mutual exclusion of threads across my
      global variables, I opted not to take this approach in lieu of the
       simpier sequential implementation. Thus, this version of **ping** cannot send additional packets in the "background" while it is
        waiting for a packet to come in. However, if if I had
        more
        time, 
refactoring my implementation to utilize different sender/receiver threads
 would be one of my top priorities.  
 
 
## References 

 1. http://www.ping127001.com/pingpage.htm
 2. https://www.cs.utah.edu/~swalton/listings/sockets/programs/part4/chap18/myping.c
 3. https://www.tenouk.com/Module43a.html
 4. https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
 5. https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
 6. https://www.geeksforgeeks.org/internet-control-message-protocol-icmp/
 7. https://www.johndcook.com/blog/standard_deviation/
 

