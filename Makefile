all: recv 

recv : gmn_mod.o 
	cc -m32 -Wall -o recv -Xlinker "-(" libsc.a gmn_mod.o -lpthread  

gmn_mod.o : gmn_mod.h ftl_msg.h
	cc -m32 -Wall -c -o gmn_mod.o gmn_mod.c 

clean:
	rm *.o recv
