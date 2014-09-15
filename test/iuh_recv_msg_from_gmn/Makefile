all: recv

recv : libsc_msg_recv.o 
	cc -m32 -g -o recv -Xlinker "-(" ./libsc.a libsc_msg_recv.o -lpthread  

libsc_msg_recv.o : ftl_msg.h
	cc -m32 -c -g -o libsc_msg_recv.o libsc_msg_recv.c

clean:
	rm *.o recv
