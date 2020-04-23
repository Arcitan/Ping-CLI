CC = cc
CFLAGS = -std=gnu11 -Wall -Wextra -Werror -g
LDFLAGS = -lpthread -lnsl -lrt -lm


all: ping

ping: ping.c
	${CC} ${CFLAGS} -o ping ping.c ${LDFLAGS}

clean:
	${RM} *.o ping core.[1-9]*

.PHONY: all clean
