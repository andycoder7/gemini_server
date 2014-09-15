all: recv

recv : libsc_msg_recv.o 
	cc -g -o recv -Xlinker "-(" ./libsc.a libsc_msg_recv.o -lpthread  

libsc_msg_recv.o : ftl_msg.h
	cc -c -g -o libsc_msg_recv.o libsc_msg_recv.c

clean:
	rm *.o recv
