/*****************************************************************************
 *
 *      proxyDriver.c
 *      
 *      Isabel Muste (imuste01)
 *      Marti Zentmaier (mzentm01)
 *
 *      11/10/2024
 *      
 *      CS 112 Final Project
 * 
 *      This file contains the initialization for the proxy program
 *      
 *
 *****************************************************************************/

#include "include.h"
#include "proxy.h"
#include "logging.h"


int getProxyMode(char *modeCommand);
void printUsage();


/*
 * name:      main
 * purpose:   opens the commands file and initializes a new cache instance
 * arguments: argc, argv
 * returns:   exit success
 * effects:   none
 */
int main(int argc, char *argv[])
{       
        if (argc < 3) {
                printUsage();
        }

        int port = atoi(argv[1]);
        int mode = getProxyMode(argv[2]);

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        SSL_library_init();
        SSL_load_error_strings();

        cacheInfo *thisCache = newCache(100);
        proxy *thisProxy = newProxy(port, thisCache, mode);


        initializeClientContext(thisProxy);
        initializeRootCert(thisProxy);
        initializeCategories(thisProxy);
        proxyListening(thisProxy);

        // freeMemory(thisCache);
        X509_free(thisProxy->rootCert);
        EVP_PKEY_free(thisProxy->rootKey);


        return EXIT_SUCCESS;
}


/*
 * name:      getProxyMode
 * purpose:   gets the proxy mode from the command line argument
 * arguments: the command line argument
 * returns:   the proxy mode
 * effects:   none
 */
int getProxyMode(char *modeCommand)
{
        if (strncmp(modeCommand, "--mode=", 7) == 0) {
                char *mode = modeCommand + 7;

                if (strcmp(mode, "tunnel") == 0) {
                        printf("Mode set to tunnel: proxy won't decrypt any requests.\n");
                        return 0;
                } 
                else if (strcmp(mode, "MITM") == 0) {
                        printf("Mode set to MITM: proxy will decrypt all traffic.\n");
                        return 1;
                } 
                else {
                        printf("Invalid mode specified.\n");
                        printUsage();
                }
        } 
        else {
                printUsage();
        }

        return -1;
}


/*
 * name:      printUsage
 * purpose:   prints the usage when the user enters the wrong commands
 * arguments: none
 * returns:   none
 * effects:   none
 */
void printUsage()
{
        printf("\nUsage: ./proxy port --mode=<mode>\n");
        printf("Available modes: \n");
        printf("  tunnel: the proxy won't decrypt any requests\n");
        printf("  MITM: the proxy will decrypt all traffic\n\n");
        exit(EXIT_FAILURE);
}

