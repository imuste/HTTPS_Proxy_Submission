# ! /bin/sh

gcc -DERROR -DDEBUG -DINFO -c proxyDriver.c proxy.c cache.c mitm.c tunnel.c LLM.c
g++ -DERROR -DDEBUG -DINFO -c MurmurHash3.cpp
g++ -DERROR -DDEBUG -DINFO -o proxy proxyDriver.o proxy.o cache.o MurmurHash3.o LLM.o mitm.o tunnel.o -lssl -lcrypto -lcurl