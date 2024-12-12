/*****************************************************************************
 *
 *      include.h
 *      
 *      Marti Zentmaier (mzentm01)
 *      Isabel Muste (imuste01)
 * 
 *      11/10/2024
 *      
 *      CS 112 Final Project
 * 
 *      Contains the included libraries for the entire proxy program
 *
 *
 *****************************************************************************/


#ifndef INCLUDE_H
#define INCLUDE_H

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <math.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <limits.h>
#include <time.h> 
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


#endif // INCLUDE_H