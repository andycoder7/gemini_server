all: send

send : libsc_msg_send.o
	cc -g -o send -Xlinker "-(" ./libsc.a libsc_msg_send.o -lpthread  

libsc_msg_send.o : ftl_msg.h
	cc -c -g -o libsc_msg_send.o libsc_msg_send.c

clean:
	rm *.o send
