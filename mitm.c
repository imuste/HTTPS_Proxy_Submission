/*****************************************************************************
 *
 *      mitm.c
 *      
 *      Isabel Muste (imuste01)
 *      Marti Zentmaier (mzentm01)
 * 
 *      11/10/2024
 *      
 *      CS 112 Final Project
 * 
 *      This file contains the proxy MITM configuration. It reads and writes
 *      data to and from the client and server and does encryption / 
 *      decryption. It also contains the logic for setting up / signing 
 *      certificates, as well as the NYT connections game logic.
 *      
 *
 *****************************************************************************/

#include "proxy.h"
#include "logging.h"

#define TUNNEL 0
#define MITM 1
#define BR 1
#define GZIP 2


static long serialNumCounter = 2;

/*****************************************************************************
*                               MITM SETUP
******************************************************************************/


/*
 * name:      initializeClientContext
 * purpose:   initializes the client context used throughout the program for 
 *            different client SSL objects
 * arguments: the proxy instance
 * returns:   none
 * effects:   none
 */
void initializeClientContext(proxy *theProxy) 
{
        DEBUG_PRINT("FUNCTION: initializeClientContext");

        // create a method to act like a server
        const SSL_METHOD *method = TLS_server_method();
        checkFatalNullSSL((void *)method);

        // create a new client context
        theProxy->clientCtx = SSL_CTX_new(method);
        checkFatalNullSSL(theProxy->clientCtx);

        // Load certificate and key
        if (SSL_CTX_use_certificate_file(theProxy->clientCtx, 
                "certs/ca-cert.pem", SSL_FILETYPE_PEM) <= 0
                || SSL_CTX_use_PrivateKey_file(theProxy->clientCtx, 
                "certs/ca-key.pem", SSL_FILETYPE_PEM) <= 0
                || !SSL_CTX_check_private_key(theProxy->clientCtx)) {
                
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(theProxy->clientCtx);
                exit(EXIT_FAILURE);
        }

        SSL_CTX_set_cipher_list(theProxy->clientCtx, "DEFAULT");
}


/*
 * name:      initializeRootCert
 * purpose:   opens the root certificate and key files, to store references to 
 *            their SSL objects
 * arguments: the proxy instance
 * returns:   none
 * effects:   none
 */
void initializeRootCert(proxy *theProxy) 
{
        DEBUG_PRINT("FUNCTION: initializeRootCert");

        const char *rootCertPath = "certs/ca-cert.pem";
        const char *rootKeyPath = "certs/ca-key.pem";

        FILE *rootCertFile = fopen(rootCertPath, "r");
        theProxy->rootCert = PEM_read_X509(rootCertFile, NULL, NULL, NULL);
        fclose(rootCertFile);

        FILE *rootKeyFile = fopen(rootKeyPath, "r");
        theProxy->rootKey = PEM_read_PrivateKey(rootKeyFile, NULL, NULL, NULL);
        fclose(rootKeyFile);
}



/******************************************************************************
*                         CLIENT / SERVER SSL SETUP
******************************************************************************/


/*
 * name:      setupServerCertificate
 * purpose:   sets up the certificate for the necessary domain allowing the 
 *            proxy to impersonate the target server
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
bool setupServerCertificate(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: setupServerCertificate");

        const char *domain = 
                theProxy->clientTable[slot].slotArray[index].serverURL;
        int clientSD = theProxy->clientTable[slot].slotArray[index].clientSD;

        // create a new key pair using RSA key generation method in OpenSSL
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (checkNullErrSSL(theProxy, slot, index, pctx, 1)) return false;
        int returnVal = EVP_PKEY_keygen_init(pctx);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 2)) return false;
        returnVal = EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 3)) return false;
        EVP_PKEY *serverKey = NULL;
        returnVal = EVP_PKEY_keygen(pctx, &serverKey);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 4)) return false;
        EVP_PKEY_CTX_free(pctx);

        // create a new X.509 certificate, version 3, serial nr 1
        X509 *serverCert = X509_new();
        if (checkNullErrSSL(theProxy, slot, index, serverCert, 5)) return false;
        returnVal = X509_set_version(serverCert, 2);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 6)) return false;
        returnVal = ASN1_INTEGER_set(X509_get_serialNumber(serverCert), 
                serialNumCounter++);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 7)) return false;

        // set validity period from now to 1 year from now
        X509_gmtime_adj(X509_get_notBefore(serverCert), 0);
        X509_gmtime_adj(X509_get_notAfter(serverCert), 31536000L);

        // set subject and root issuer
        X509_NAME *name = X509_get_subject_name(serverCert);
        if (checkNullErrSSL(theProxy, slot, index, name, 8)) return false;
        returnVal = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                (unsigned char *)domain, -1, -1, 0);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 9)) return false;
        returnVal = X509_set_issuer_name(serverCert, 
                X509_get_subject_name(theProxy->rootCert));
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 10)) return false;
        if (!addSubjectAltName(serverCert, domain)) {
                return false;
        }

        // set the public key and sign certificate with root key
        returnVal = X509_set_pubkey(serverCert, serverKey);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 11)) return false;
        returnVal = X509_sign(serverCert, theProxy->rootKey, EVP_sha256());
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 12)) return false;

        theProxy->clientTable[slot].slotArray[index].serverCert = serverCert;
        theProxy->clientTable[slot].slotArray[index].serverKey = serverKey;

        return true;
}


/*
 * name:      addSubjectAltName
 * purpose:   sets the SAN field of a certificate, to ensure browser 
 *            compatibility
 * arguments: the X509 certificate, the domain name
 * returns:   true if the extension was successful, false otherwise
 * effects:   none
 */
bool addSubjectAltName(X509 *cert, const char *domain) 
{
        GENERAL_NAME *genName = GENERAL_NAME_new();
        if (genName == NULL) {
                ERROR_PRINT("Failed to create GENERAL_NAME\n");
                return false;
        }

        // Set the SAN to the domain name
        ASN1_IA5STRING *asn1Str = ASN1_IA5STRING_new();
        if (!asn1Str || !ASN1_STRING_set(asn1Str, domain, strlen(domain))) {
                ERROR_PRINT("Failed to set SAN string\n");
                GENERAL_NAME_free(genName);
                return false;
        }

        GENERAL_NAME_set0_value(genName, GEN_DNS, asn1Str);

        // Create a stack of GENERAL_NAME
        STACK_OF(GENERAL_NAME) *sanList = sk_GENERAL_NAME_new_null();
        if (!sanList || !sk_GENERAL_NAME_push(sanList, genName)) {
                ERROR_PRINT("Failed to create SAN list\n");
                GENERAL_NAME_free(genName);
                if (sanList) sk_GENERAL_NAME_free(sanList);
                return false;
        }

        // Convert the stack to an X509_EXTENSION
        X509_EXTENSION *sanExt = 
                X509V3_EXT_i2d(NID_subject_alt_name, 0, sanList);
        if (!sanExt) {
                ERROR_PRINT("Failed to create SAN extension\n");
                sk_GENERAL_NAME_pop_free(sanList, GENERAL_NAME_free);
                return false;
        }

        // Add the extension to the certificate
        if (!X509_add_ext(cert, sanExt, -1)) {
                DEBUG_PRINT("Failed to add SAN extension to certificate\n");
                return false;
        }

        // Cleanup
        X509_EXTENSION_free(sanExt);
        sk_GENERAL_NAME_pop_free(sanList, GENERAL_NAME_free);
        return true;
}


/*
 * name:      sendCertificateToClient
 * purpose:   does the TLS handshake with the client using the generated 
 *            certificate and key
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
bool sendCertificateToClient(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: sendCertificateToClient\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        int clientSD = client->clientSD;
        X509 *serverCert = client->serverCert;
        EVP_PKEY *serverKey = client->serverKey;

        // Create the SSL object for the client and attach the socket
        SSL *clientSSL = SSL_new(theProxy->clientCtx);
        if (checkNullErrSSL(theProxy, slot, index, clientSSL, 13)) return false;
        client->clientSSL = clientSSL;

        // Connect the SD to the SSL object
        int returnVal = SSL_set_fd(clientSSL, clientSD);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 14)) return false;

        // Use the loaded certificate for the TLS handshake
        returnVal = SSL_use_certificate(clientSSL, serverCert);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 15)) return false;

        // Use the loaded key for the TLS handshake
        returnVal = SSL_use_PrivateKey(clientSSL, serverKey);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 16)) return false;

        // Perform the TLS handshake with the client
        returnVal = SSL_accept(clientSSL);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 17)) return false;

        setSDNonBlocking(clientSD);
        SSL_set_mode(clientSSL, SSL_MODE_ASYNC);
        
        return true;
}


/*
 * name:      connectToServer
 * purpose:   connects the proxy to the target server
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if successful, false otherwise
 * effects:   none
 */
bool connectToServer(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: connectToServer\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        //get host IP address
        char *hostName = client->serverURL; 
        struct hostent *hostInfo = gethostbyname(hostName);
        if (checkNullErrSSL(theProxy, slot, index, hostInfo, 18)) return false;

        //send the file contents to proxy
        struct sockaddr_in serverAddress;

        int serverSD = socket(AF_INET, SOCK_STREAM, 0);
        if (checkNegOneErrSSL(theProxy, slot, index, serverSD, 19)) return false;
        client->serverSD = serverSD;

        //ensure to close the socket and port after termination
        int opt = 1;
        int returnVal = 
                setsockopt(serverSD, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (checkNegOneErrSSL(theProxy, slot, index, returnVal, 20)) return false;

        //Client setup to connect the socket to the server and its IP address
        //this is the setup specifying the server info
        memset(&serverAddress, 0, sizeof(struct sockaddr_in));
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr = *(struct in_addr *)hostInfo->h_addr;
        serverAddress.sin_port = htons(client->serverPort);
        returnVal = connect(serverSD, (struct sockaddr *)&serverAddress, 
                sizeof(serverAddress));
        if (checkNegOneErrSSL(theProxy, slot, index, returnVal, 21)) return false;
        
        // add serverSD to the active set for select
        FD_SET(serverSD, &theProxy->activeFDSet);
        if (serverSD > theProxy->maxFD) {
                theProxy->maxFD = serverSD;
        }

        return true;
}


/*
 * name:      connectToServer
 * purpose:   sets up a TLS connection with the target server allowing for 
 *            message relaying
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
void connectServerSSL(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: connectServerSSL\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        const SSL_METHOD *method = TLS_client_method();
        if (checkNullErrSSL(theProxy, slot, index, (void *)method, 22)) return;

        // Setup new SSL server context
        SSL_CTX *serverCtx = SSL_CTX_new(method);
        if (checkNullErrSSL(theProxy, slot, index, serverCtx, 23)) return;
        client->serverCtx = serverCtx;

        // Setup new SSL server object
        SSL *serverSSL = SSL_new(serverCtx);
        if (checkNullErrSSL(theProxy, slot, index, serverSSL, 24)) return;
        client->serverSSL = serverSSL;

        // Attach server socket to SSL object
        int returnVal = SSL_set_fd(serverSSL, client->serverSD);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 25)) return;

        // Perform SSL/TLS handshake with the server
        returnVal = SSL_connect(serverSSL);
        if (checkNegErrSSL(theProxy, slot, index, returnVal, 26)) return;

        if (!populateServerStructSSL(theProxy, client)) {
                removeClient(theProxy, slot, index);
        }

        setSDNonBlocking(client->serverSD);
        SSL_set_mode(serverSSL, SSL_MODE_ASYNC);
}


/*
 * name:      populateServerStructSSL
 * purpose:   populates the relevant fields in the server struct
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if successful, false otherwise
 * effects:   none
 */
bool populateServerStructSSL(proxy *theProxy, connectionInfo *client)
{
        DEBUG_PRINT("FUNCTION: populateServerStructSSL\n");
        int serverSlot = hashTableKey(theProxy, client->serverSD);
        int serverIndex = theProxy->clientTable[serverSlot].numSlotItems;
        theProxy->numClients++;
        theProxy->clientTable[serverSlot].numSlotItems++;

        connectionInfo *server = 
                &theProxy->clientTable[serverSlot].slotArray[serverIndex];

        server->clientSD = client->clientSD;
        server->serverSD = client->serverSD;
        server->isClient = false;
        server->connActive = true;
        server->serverPort = client->serverPort;
        server->serverSSL = client->serverSSL;
        server->clientSSL = client->clientSSL;
        server->serverCtx = client->serverCtx;
        
        int URLLength = strlen(client->serverURL);
        server->serverURL = malloc(URLLength + 1);
        if (checkNullErrSSL(theProxy, serverSlot, serverIndex, 
                server->serverURL, 1)) {
                return false;
        }

        memcpy(server->serverURL, client->serverURL, URLLength);
        server->serverURL[URLLength] = '\0';
        return true;
}



/******************************************************************************
*                        SSL CLIENT TO SERVER RELAYING
******************************************************************************/


/*
 * name:      relayClientToServerSSL
 * purpose:   relays the message from the client to the server 
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
void relayClientToServerSSL(proxy *theProxy, int slot, int index) 
{
        DEBUG_PRINT("FUNCTION: relayClientToServerSSL\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        if (checkNullErrSSL(theProxy, slot, index, client->clientSSL, 27)) return;
        int buffSize = 100000;
        char *readBuffer = malloc(buffSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, readBuffer, 28)) return;

        // read from the client
        int bytesRead = readFromClientSSL(theProxy, slot, index, 
                client->clientSSL, readBuffer, buffSize);
        if (bytesRead == -1) {
                return;
        }
        
        // check if the serverSSL is null
        if (checkNullErrSSL(theProxy, slot, index, client->serverSSL, 29)) return;

        // write to the server
        int writeReturn = writeToServerSSL(theProxy, slot, index, 
                client->serverSSL, client->readBuffer, bytesRead);
        if (writeReturn == -1) {
                return;
        }

        if (client->readBuffer != NULL) {
                free(client->readBuffer);
                client->readBuffer = NULL;
        }
        client->bufferRead = 0;
        client->bufferSize = -1;
}


/*
 * name:      readFromClientSSL
 * purpose:   reads data from the client and stores this in the buffer 
 * arguments: the proxy instance, the slot and index in the table, the SSL 
 *            object to read from, the read buffer and bufferSize
 * returns:   number of bytes successfully read, or -1 on error
 * effects:   none
 */
int readFromClientSSL(proxy *theProxy, int slot, int index, SSL *clientSSL, 
        char *readBuffer, int bufferSize)
{
        DEBUG_PRINT("FUNCTION: readFromClientSSL\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        int readReturn = SSL_read(clientSSL, readBuffer, bufferSize);

        if (checkWantReadWrite(theProxy, clientSSL, readReturn, 30)) return -1;        
        if (checkNegErrSSL(theProxy, slot, index, readReturn, 31)) return -1;
        if (checkNullErrSSL(theProxy, slot, index, readBuffer, 32)) return -1;
        readBuffer[readReturn] = '\0';

        client->readBuffer = readBuffer;
        client->bufferSize = readReturn;

        if ((strncmp(client->serverURL, "www.nytimes.com", 15) == 0)) {
                if (!handleClientConnectionsData(theProxy, slot, index)) {
                        return -1;
                }
        }
        
        return client->bufferSize;
}


/*
 * name:      writeToServerSSL
 * purpose:   writes the client data to the server
 * arguments: the proxy instance, the slot and index in the table, the SSL 
 *            object to write to, the buffer and bufferSize
 * returns:   number of bytes successfully written, or -1 on error
 * effects:   none
 */
int writeToServerSSL(proxy *theProxy, int slot, int index, SSL *serverSSL, 
        char *readBuffer, int readReturn)
{
        DEBUG_PRINT("FUNCTION: writeToServerSSL\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        int totalSent = 0;
        while (totalSent < readReturn) {
                int writeReturn = SSL_write(serverSSL, readBuffer + totalSent, 
                        readReturn - totalSent);
                if (checkWantReadWrite(theProxy, serverSSL, writeReturn, 33)) return -1;
                if (checkNegErrSSL(theProxy, slot, index, writeReturn, 34)) return -1;

                totalSent += writeReturn;
        }

        return totalSent;
}



/******************************************************************************
*                        SSL SERVER TO CLIENT RELAYING
******************************************************************************/


/*
 * name:      relayServerToClientSSL
 * purpose:   relays the message from the server to the client 
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
void relayServerToClientSSL(proxy *theProxy, int slot, int index) 
{
        DEBUG_PRINT("FUNCTION: relayServerToClientSSL\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];
        if (checkNullErrSSL(theProxy, slot, index, server->serverSSL, 35)) return;
        int bufferSize = 100000;
        char *readBuffer = malloc(bufferSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, readBuffer, 36)) return;

        // read from the server
        int readReturn = 
        readFromServerSSL(theProxy, slot, index, server->serverSSL, 
                readBuffer, bufferSize);
        if (readReturn == -1) {
                return;
        }
        
        // check if the clientSSL is null
        if (checkNullErrSSL(theProxy, slot, index, server->clientSSL, 37)) return;

        // write to the client
        int writeReturn = 
        writeToClientSSL(theProxy, slot, index, server->clientSSL, 
                server->readBuffer, readReturn);
        if (writeReturn == -1) {
                return;
        }

        if (server->readBuffer != NULL) {
                free(server->readBuffer);
                server->readBuffer = NULL;
        }
        server->bufferRead = 0;
        server->bufferSize = -1;

        if (server->contentRead == server->contentSize) {
                if (server->msgHeader != NULL) {
                        free(server->msgHeader);
                        server->msgHeader = NULL;
                }
                server->headerRead = 0;
                server->headerSize = -1;
                if (server->msgContent != NULL) {
                        free(server->msgContent);
                        server->msgContent = NULL;
                }
                server->contentRead = 0;
                server->contentSize = -1;
        }
}



/*
 * name:      readFromServerSSL
 * purpose:   reads data from the server and stores this in the buffer
 * arguments: the proxy instance, the slot and index in the table, the SSL 
 *            object to read from, the read buffer and bufferSize
 * returns:   number of bytes successfully read, or -1 on error
 * effects:   populates the struct header and content fields
 */
int readFromServerSSL(proxy *theProxy, int slot, int index, SSL *serverSSL, 
        char *readBuffer, int bufferSize)
{
        DEBUG_PRINT("FUNCTION: readFromServerSSL\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];

        int readReturn = SSL_read(serverSSL, readBuffer, bufferSize);
        if (checkWantReadWrite(theProxy, serverSSL, readReturn, 38)) return -1;        
        if (checkNegErrSSL(theProxy, slot, index, readReturn, 39)) return -1;
        if (checkNullErrSSL(theProxy, slot, index, readBuffer, 40)) return -1;
        readBuffer[readReturn] = '\0';

        server->readBuffer = readBuffer;
        server->bufferSize = readReturn;

        if ((strncmp(server->serverURL, "www.nytimes.com", 15) == 0)) {
                if (!handleServerConnectionsData(theProxy, slot, index)) {
                        return -1;
                }
                if (server->contentRead == server->contentSize) {
                        char *fullBuffer = malloc(server->headerSize + server->contentSize + 1);
                        memcpy(fullBuffer, server->msgHeader, server->headerSize);
                        memcpy(fullBuffer + server->headerSize, server->msgContent, server->contentSize);
                        free(server->readBuffer);
                        server->readBuffer = fullBuffer;
                        server->bufferSize = server->headerSize + server->contentSize;
                        server->readBuffer[server->headerSize + server->contentSize] = '\0';
                        return server->bufferSize;
                }
                return 0;
        }

        return server->bufferSize;
}


/*
 * name:      writeToClientSSL
 * purpose:   writes the server data to the client
 * arguments: the proxy instance, the slot and index in the table, the SSL 
 *            object to write to, the buffer and bufferSize
 * returns:   number of bytes successfully written, or -1 on error
 * effects:   none
 */
int writeToClientSSL(proxy *theProxy, int slot, int index, SSL *clientSSL, 
        char *readBuffer, int readReturn)
{
        DEBUG_PRINT("FUNCTION: writeToClientSSL\n");
        int totalSent = 0;
        while (totalSent < readReturn) {
                int writeReturn = SSL_write(clientSSL, readBuffer + totalSent, 
                        readReturn - totalSent);

                if (checkWantReadWrite(theProxy, clientSSL, writeReturn, 41)) return -1;
                if (checkNegErrSSL(theProxy, slot, index, writeReturn, 42)) return -1;

                totalSent += writeReturn;
        }

        return totalSent;
}





/******************************************************************************
*                         POPULATE CLIENT FIELDS
******************************************************************************/


/*
 * name:      handleClientConnectionsData
 * purpose:   drives the process of retrieving header and content data from the
 *            buffer read by the read call
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   none
 */
bool handleClientConnectionsData(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: handleClientConnectionsData\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        if (client->headerSize > 0) {
                if (client->msgHeader != NULL) {
                        free(client->msgHeader);
                        client->msgHeader = NULL;
                }
                client->headerRead = 0;
                client->headerSize = -1;
        }
        if (client->contentRead == client->contentSize) {
                if (client->msgContent != NULL) {
                        free(client->msgContent);
                        client->msgContent = NULL;
                }
                client->contentRead = 0;
                client->contentSize = -1;
        }

        if (!populateClientRequestFields(theProxy, slot, index)) {
                return false;
        }

        if (!getConnectionGuess(theProxy, slot, index)) {
                return false;
        }

        return true;
}


/*
 * name:      populateClientRequestFields
 * purpose:   determines whether the information in the read buffer is for 
 *            a header or data. Gets the content length and removes the 
 *            encoding field when full header is stored
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   none
 */
bool populateClientRequestFields(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: populateClientRequestFields\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        // header field is empty or partially populated
        if ((client->headerRead <= 0) || (client->headerSize <= 0)) {
                if (!populateClientHeaderField(theProxy, slot, index)) {
                        return false;
                }
                if (client->headerSize > 0) {
                        getContentLength(theProxy, slot, index, 
                                client->msgHeader, client->headerSize);
                        removeAcceptEncoding(theProxy, slot, index);
                }
        }
        else if ((client->contentRead < client->contentSize)) {
                if (!populateClientContentField(theProxy, slot, index)) {
                        return false;
                }
        }

        return true;
}


/*
 * name:      populateClientHeaderField
 * purpose:   populates the client header fields with the buffer contents
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   populates the header and/or content struct fields
 */
bool populateClientHeaderField(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: populateClientHeaderField\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        int headerSize = checkEndDelimiter(theProxy, slot, index, 
                client->readBuffer, client->bufferSize);
        int headerRead = client->headerRead;

        // header is incomplete
        if (headerSize == -1) {
                char *completeHeader = malloc(headerRead + client->bufferSize);
                if (checkNullErrSSL(theProxy, slot, index, completeHeader, 43)) return false;
                memcpy(completeHeader, client->msgHeader, headerRead);
                memcpy(completeHeader + headerRead, client->readBuffer, 
                        client->bufferSize);
                client->msgHeader = completeHeader;
                client->headerRead += client->bufferSize;
                return true;
        }

        char *completeHeader = malloc(headerRead + headerSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, completeHeader, 44)) return false;
        memcpy(completeHeader, client->msgHeader, headerRead);
        memcpy(completeHeader + headerRead, client->readBuffer, headerSize);
        completeHeader[headerRead + headerSize] = '\0';

        if (client->msgHeader != NULL) {
                free(client->msgHeader);
                client->msgHeader = NULL;
        }
        client->msgHeader = completeHeader;
        client->headerRead = headerRead + headerSize;
        client->headerSize = headerRead + headerSize;

        // read leftover server content
        if (headerSize < client->bufferSize) {
                client->msgContent = malloc(client->bufferSize - headerSize + 1);
                if (checkNullErrSSL(theProxy, slot, index, client->msgContent, 45)) return false;
                memcpy(client->msgContent, client->readBuffer + headerSize, 
                        client->bufferSize - headerSize);
                client->msgContent[client->bufferSize - headerSize] = '\0';
                client->contentRead = client->bufferSize - headerSize;
        }

        return true;
}


/*
 * name:      populateClientContentField
 * purpose:   populates the client content fields with the buffer contents
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   populates the content struct fields
 */
bool populateClientContentField(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: populateClientContentField\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        int contentRead = client->contentRead;
        int contentSize = client->contentSize;

        char *completeContent = malloc(contentRead + client->bufferSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, completeContent, 46)) return false;

        if (client->msgContent != NULL) {
                memcpy(completeContent, client->msgContent, contentRead);
        }
        memcpy(completeContent + contentRead, client->readBuffer, client->bufferSize);
        completeContent[contentRead + client->bufferSize] = '\0';
        if (client->msgContent != NULL) {
                free(client->msgContent);
                client->msgContent = NULL;
        }
        client->msgContent = completeContent;
        client->contentRead += client->bufferSize;

        return true;
}


/*
 * name:      getConnectionGuess
 * purpose:   inspects the content of the client to determine if a connections 
 *            guess was made
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   none
 */
bool getConnectionGuess(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: getConnectionGuess\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        if (client->msgContent == NULL) {
                return true;
        }

        //check if we have found end of header delimiter
        char *guessStart = "r: fail";
        char *guessEnd = "d: null";
        char *start = strstr(client->msgContent, guessStart);
        char *end = strstr(client->msgContent, guessEnd);
        if (start == NULL) {
                return true;
        }

        int startPoint = start - client->msgContent;
        int guessSize = end - start;
        char *guess = malloc(guessSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, guess, 47)) return false;

        memcpy(guess, client->msgContent + startPoint, guessSize);
        guess[guessSize] = '\0';
        INFO_PRINT("GUESS: %s\n", guess);
        theProxy->connGuess = guess;

        return true;
}



/******************************************************************************
*                         POPULATE SERVER FIELDS
******************************************************************************/


/*
 * name:      handleServerConnectionsData
 * purpose:   drives the process of retrieving header and content data from the
 *            buffer read by the read call
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   none
 */
bool handleServerConnectionsData(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: handleServerConnectionsData\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];

        if (!populateServerResponseFields(theProxy, slot, index)) {
                return false;
        }
        if (!getConnectionSolution(theProxy, slot, index)) {
                return false;
        }

        if (server->contentSize == server->contentRead) {
                if (!addDivToContent(theProxy, slot, index)) {
                        return false;
                }
        }

        return true;
}



/*
 * name:      populateServerResponseFields
 * purpose:   populates the server header and/or content fields with data from 
 *            the server read call
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   populates the header and/or content struct fields
 */
bool populateServerResponseFields(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: populateServerResponseFields\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];

        // header field is empty or partially populated
        if ((server->headerRead <= 0) || (server->headerSize <= 0)) {
                if (!populateServerHeaderField(theProxy, slot, index)) {
                        return false;
                }
                if (server->headerSize > 0) {
                        getContentLength(theProxy, slot, index, 
                                server->msgHeader, server->headerSize);
                }
        }

        // header field is complete, but content field is (partially empty)
        else if ((server->contentRead < server->contentSize)) {
                if (!populateServerContentField(theProxy, slot, index)) {
                        return false;
                }
        }
        return true;
}


/*
 * name:      populateServerHeaderField
 * purpose:   populates the server header field with data from the read buffer
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   populates the header struct fields
 */
bool populateServerHeaderField(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: populateServerHeaderField\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];
        int headerSize = checkEndDelimiter(theProxy, slot, index, 
                server->readBuffer, server->bufferSize);
        int headerRead = server->headerRead;

        // header is incomplete
        if (headerSize == -1) {
                char *completeHeader = malloc(headerRead + server->bufferSize + 1);
                if (checkNullErrSSL(theProxy, slot, index, completeHeader, 48)) return false;
                memcpy(completeHeader, server->msgHeader, headerRead);
                memcpy(completeHeader + headerRead, server->readBuffer, 
                        server->bufferSize);
                completeHeader[headerRead + server->bufferSize] = '\0';
                if (server->msgHeader != NULL) {
                        free(server->msgHeader);
                        server->msgHeader = NULL;
                }
                server->msgHeader = completeHeader;
                server->headerRead += server->bufferSize;
                return true;
        }

        char *completeHeader = malloc(headerRead + headerSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, completeHeader, 49)) return false;
        memcpy(completeHeader, server->msgHeader, headerRead);
        memcpy(completeHeader + headerRead, server->readBuffer, headerSize);
        completeHeader[headerRead + headerSize] = '\0';

        if (server->msgHeader != NULL) {
                free(server->msgHeader);
                server->msgHeader = NULL;
        }
        server->msgHeader = completeHeader;
        server->headerRead = headerRead + headerSize;
        server->headerSize = headerRead + headerSize;

        // read leftover server content
        if (headerSize < server->bufferSize) {
                server->msgContent = malloc(server->bufferSize - headerSize + 1);
                if (checkNullErrSSL(theProxy, slot, index, server->msgContent, 50)) return false;
                memcpy(server->msgContent, server->readBuffer + headerSize, 
                        server->bufferSize - headerSize);
                server->msgContent[server->bufferSize - headerSize] = '\0';
                server->contentRead = server->bufferSize - headerSize;
        }

        return true;
}


/*
 * name:      populateServerContentField
 * purpose:   populates the server content field either stream wise or chunked 
 *            wise
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   none
 */
bool populateServerContentField(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: populateServerContentField\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];
        // if (server->chunkedContent) {
        //         return readContentChunks(theProxy, slot, index);
        // }
        // else {
                return readContentStream(theProxy, slot, index);
        // }
}


/*
 * name:      readContentChunks
 * purpose:   reads the content chunks and populates the struct fields
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   none
 */
bool readContentChunks(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: readContentChunks\n");
        // handle the case where a part of the chunk was previously read
        

        return true;
}


/*
 * name:      readContentStream
 * purpose:   reads the content stream and populates the struct fields
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   none
 */
bool readContentStream(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: readContentStream\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];
        int contentRead = server->contentRead;
        int contentSize = server->contentSize;

        char *completeContent = malloc(contentRead + server->bufferSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, completeContent, 51)) return false;

        if (server->msgContent != NULL) {
                memcpy(completeContent, server->msgContent, contentRead);
        }
        memcpy(completeContent + contentRead, server->readBuffer, server->bufferSize);
        completeContent[contentRead + server->bufferSize] = '\0';
        if (server->msgContent != NULL) {
                free(server->msgContent);
                server->msgContent = NULL;
        }
        server->msgContent = completeContent;
        server->contentRead += server->bufferSize;
        return true;
}


/*
 * name:      getConnectionSolution
 * purpose:   determines if the content struct field contains the connections
 *            solution and formats it if so
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   none
 */
bool getConnectionSolution(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: getConnectionSolution\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];

        if (server->msgContent == NULL) {
                return true;
        }

        // check if we have found end of header delimiter
        char *solStart = "status\":\"OK\"";
        char *solEnd = "}]}]}";
        char *start = strstr(server->msgContent, solStart);
        char *end = strstr(server->msgContent, solEnd);
        if (start == NULL) {
                return true;
        }

        int startPoint = start - server->msgContent;
        int solSize = end - start;
        char *solution = malloc(solSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, solution, 52)) return false;

        memcpy(solution, server->msgContent + startPoint, solSize);
        solution[solSize] = '\0';
        theProxy->connSolution = solution;
        INFO_PRINT("FOUND SOLUTION: %s\n", solution);

        formatConnectionsSolution(theProxy, solution);
        return true;
}


/*
 * name:      addDivToContent
 * purpose:   adds the div with the styling and hints to the content buffer to 
 *            be sent to the browser
 * arguments: the proxy instance, the slot and index in the table
 * returns:   true if no error occurred, false otherwise
 * effects:   none
 */
bool addDivToContent(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: addDivToContent\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];
        if (server->msgContent == NULL || server->contentSize < 7) {
                return true;
        }

        // check if we have found end of header delimiter
        char *bodyTag = "</body>";
        char *ourTag = "M+I_Proxy";
        char *htmlTag = "<!DOCTYPE html>";
        char *start = strstr(server->msgContent, bodyTag);
        char *divAdded = strstr(server->msgContent, ourTag);
        char *htmlAdded = strstr(server->msgContent, htmlTag);
        if (divAdded != NULL || start == NULL || htmlAdded == NULL) {
                return true;
        }

        makeLLMCall(theProxy);

        // right before end body 
        int startPoint = start - server->msgContent;
        int finalLength = strlen(theProxy->LLMResponse);
        char *divContent = theProxy->LLMResponse;

        // copy over new div structure into buffer
        char *newContent = malloc(server->contentSize + finalLength + 1);
        memcpy(newContent, server->msgContent, startPoint);
        memcpy(newContent + startPoint, divContent, finalLength);
        memcpy(newContent + startPoint + finalLength, server->msgContent + startPoint, 
                server->contentRead - startPoint);
        newContent[server->contentRead + finalLength] = '\0';
        
        free(server->msgContent);
        server->msgContent = newContent;
        server->contentRead += finalLength;

        setContentLength(theProxy, slot, index, finalLength);
        return true;
}



bool addEmptyDivToContent(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: addEmptyDivToContent\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];
        if (server->msgContent == NULL) {
                return true;
        }

        char *newBuffer = malloc(server->contentSize + 1);
        memcpy(newBuffer, server->msgContent, server->contentRead);
        memset(newBuffer + server->contentRead, ' ', 1000);
        newBuffer[server->contentSize] = '\0';

        free(server->msgContent);
        server->msgContent = newBuffer;
        server->contentRead += 1000;
        return true;
}




bool addDivToBuffer(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: addDivToBuffer\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];
        if (server->readBuffer == NULL) {
                return true;
        }

        // check if we have found end of header delimiter
        char *bodyTag = "</body>";
        char *ourTag = "M+I_Proxy";
        char *start = strstr(server->readBuffer, bodyTag);
        char *divAdded = strstr(server->readBuffer, ourTag);
        if (divAdded != NULL || start == NULL) {
                return true;
        }

        // right before end body 
        int startPoint = start - server->readBuffer;
        char *divContent = malloc(1001);
        if (checkNullErrSSL(theProxy, slot, index, divContent, 53)) return false;
        FILE *file = fopen("divContent.txt", "r");
        size_t bytesRead = fread(divContent, 1, 1000, file);
        divContent[bytesRead] = '\0';
        fclose(file);

        // copy over new div structure into buffer
        char *newContent = malloc(server->bufferSize + 1001);
        memcpy(newContent, server->readBuffer, startPoint);
        memcpy(newContent + startPoint, divContent, 1000);
        memcpy(newContent + startPoint + 1000, server->readBuffer + startPoint, 
                server->bufferSize - startPoint);
        newContent[server->bufferSize + 1000] = '\0';
        
        free(server->readBuffer);
        server->readBuffer = newContent;
        server->bufferSize += 1000;
        return true;
}



/******************************************************************************
*                     HEADER / CONTENT PARSING FUNCTIONS
******************************************************************************/


/*
 * name:      checkEndDelimiter
 * purpose:   checks if the end of section delimiter is present in the buffer
 * arguments: the proxy instance, the slot and index in the table, the buffer, 
 *            and buffer size
 * returns:   the number of bytes before the delimiter or -1 if no end was 
 *            found
 * effects:   none
 */
int checkEndDelimiter(proxy *theProxy, int slot, int index, char *buffer, 
        int size)
{
        DEBUG_PRINT("FUNCTION: checkEndDelimiter\n");
        if (size < 4) {
                return -1;
        }

        //check if we have found end of header delimiter
        char *endOfHeader = "\r\n\r\n";
        char *endStr = strstr(buffer, endOfHeader);
        
        // header is not complete, so we can't do anything yet
        if (endStr == NULL) {
                return -1;
        }

        // the header is complete
        int headerSize = endStr - buffer + 4;
        return headerSize;
}



/*
 * name:      setContentLength
 * purpose:   sets the content length of the server header to reflect the new 
 *            size after adding the div to the content
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   alters the content header and the header size
 */
void setContentLength(proxy *theProxy, int slot, int index, int length)
{
        DEBUG_PRINT("FUNCTION: setContentLength\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        char *startPoint = NULL;

        //check if we have found end of header delimiter
        char *lengthHeader1 = "Content-Length: ";
        char *lengthHeader2 = "Content-length: ";
        char *lengthHeader3 = "content-length: ";
        char *lengthHeader4 = "content-Length: ";
        char *header1 = strstr(client->msgHeader, lengthHeader1);
        char *header2 = strstr(client->msgHeader, lengthHeader2);
        char *header3 = strstr(client->msgHeader, lengthHeader3);
        char *header4 = strstr(client->msgHeader, lengthHeader4);
        if (header1 != NULL) { startPoint = header1; }
        else if (header2 != NULL) { startPoint = header2; }
        else if (header3 != NULL) { startPoint = header3; }
        else if (header4 != NULL) { startPoint = header4; }
        else { return; }


        int lengthStart = startPoint - client->msgHeader + 16;
        char *ogEndPoint = strstr(client->msgHeader + lengthStart, "\r\n");
        int lengthEnd = ogEndPoint - client->msgHeader;
        int ogNumChars = lengthEnd - lengthStart;
        int ogLineSize = ogEndPoint - startPoint + 2;

        client->contentSize += length;
        char *newSize = malloc(ogNumChars + 10);
        int newNumChars = snprintf(newSize, ogNumChars + 10, "%d", client->contentSize);
        int charDiff = newNumChars - ogNumChars;

        char *newBuffer = malloc(client->headerSize + charDiff + 1);
        memcpy(newBuffer, client->msgHeader, lengthStart);
        memcpy(newBuffer + lengthStart, newSize, newNumChars);
        memcpy(newBuffer + lengthStart + newNumChars, client->msgHeader + lengthEnd, client->headerSize - lengthStart - ogNumChars);
        newBuffer[client->headerSize + charDiff] = '\0';

        free(client->msgHeader);
        client->msgHeader = newBuffer;
        client->headerSize += charDiff;
}


/*
 * name:      setContentEncoding
 * purpose:   checks what the content encoding field is in the provided buffer
 * arguments: the proxy instance, the slot and index in the table, the buffer, 
 *            and buffer size
 * returns:   none
 * effects:   populates the server's contentEncoding struct field
 */
void setContentEncoding(proxy *theProxy, int slot, int index, char *buffer, 
        int bufferSize)
{
        DEBUG_PRINT("FUNCTION: setContentEncoding\n");
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];
        char *currentLine;
        
        int totalRead = 0;
        while (totalRead < bufferSize) {
                currentLine = malloc(1000);
                totalRead = readLine(buffer, currentLine, totalRead);
                char *encoding = getContentEncodingLine(theProxy, currentLine);
                if (encoding != NULL) {
                        if (strncmp(encoding, "br", 2) == 0) {
                                server->contentEncoding = BR;
                        }
                        else if (strncmp(encoding, "gzip", 4) == 0) {
                                server->contentEncoding = GZIP;
                        }
                        free(currentLine);
                        return;
                        
                }
                free(currentLine);
        }
        server->contentEncoding = -1;
}




/*
 * name:      getContentEncodingLine
 * purpose:   checks a provided line and sees if it contains the content 
 *            encoding field
 * arguments: the proxy instance, the current line
 * returns:   the encoding type or NULL if the field was not found
 * effects:   none
 */
char *getContentEncodingLine(proxy *theProxy, char *currentLine)
{
        DEBUG_PRINT("FUNCTION: getContentEncodingLine\n");
        char *encodingType = NULL;

        if (currentLine[0] == 'C' || currentLine[0] == 'c') {
                bool totalWord1 = true;
                bool totalWord2 = true;
                bool totalWord3 = true;
                char *word1 = "Content-Encoding: ";
                char *word2 = "Content-encoding: ";
                char *word3 = "content-encoding: ";
                for (int i = 1; i < 18; i++) {
                        if (currentLine[i] != word1[i]) {
                                totalWord1 = false;
                        }
                        if (currentLine[i] != word2[i]) {
                                totalWord2 = false;
                        }
                        if (currentLine[i] != word3[i]) {
                                totalWord3 = false;
                        }
                }
                //we have found the get header line
                if (totalWord1 || totalWord2 || totalWord3) {
                        encodingType = malloc(strlen(currentLine) + 1);
                        checkFatalNull(encodingType);
                        strcpy(encodingType, currentLine + 18);
                        encodingType[18] = '\0';
                }
        }
        return encodingType;
}



/*
 * name:      getContentLength
 * purpose:   checks what the content length field is in the provided buffer
 * arguments: the proxy instance, the slot and index in the table, the buffer, 
 *            and buffer size
 * returns:   none
 * effects:   populates the server's contentSize struct field
 */
void getContentLength(proxy *theProxy, int slot, int index, char *buffer, 
        int bufferSize)
{
        DEBUG_PRINT("FUNCTION: getContentLength\n");
        connectionInfo *conn = &theProxy->clientTable[slot].slotArray[index];
        char *currentLine;
        bool foundChunked = false;
        
        int totalRead = 0;
        while (totalRead < bufferSize) {
                currentLine = malloc(100000);
                totalRead = readLine(buffer, currentLine, totalRead);
                char *length = getLengthLine(theProxy, currentLine);
                if (length != NULL) {
                        conn->contentSize = atoi(length);
                        return;
                }
                if (getChunkedLine(theProxy, currentLine)) {
                        foundChunked = true;
                }
                free(currentLine);
        }
        conn->contentSize = -1;

        if (foundChunked) {
                conn->chunkedContent = true;
        }
}



/*
 * name:      getLengthLine
 * purpose:   checks a provided line and sees if it contains the content 
 *            length field
 * arguments: the proxy instance, the current line
 * returns:   the content length or NULL if the line does not contain that 
 *            field
 * effects:   none
 */
char *getLengthLine(proxy *theProxy, char *currentLine)
{
        DEBUG_PRINT("FUNCTION: getLengthLine\n");
        char *contentLength = NULL;

        if (currentLine[0] == 'C' || currentLine[0] == 'c') {
                bool totalWord1 = true;
                bool totalWord2 = true;
                bool totalWord3 = true;
                char *word1 = "Content-Length: ";
                char *word2 = "Content-length: ";
                char *word3 = "content-length: ";
                for (int i = 1; i < 16; i++) {
                        if (currentLine[i] != word1[i]) {
                                totalWord1 = false;
                        }
                        if (currentLine[i] != word2[i]) {
                                totalWord2 = false;
                        }
                        if (currentLine[i] != word3[i]) {
                                totalWord3 = false;
                        }
                }
                //we have found the get header line
                if (totalWord1 || totalWord2 || totalWord3) {
                        contentLength = malloc(strlen(currentLine) + 1);
                        checkFatalNull(contentLength);
                        strcpy(contentLength, currentLine + 16);
                        contentLength[16] = '\0';
                }
        }
        return contentLength;
}



/*
 * name:      getChunkedLine
 * purpose:   checks a provided line and sees if it has the chunked transfer 
 *            encoding specified
 * arguments: the proxy instance, the current line
 * returns:   true if the line exists, false otherwise
 * effects:   none
 */
bool getChunkedLine(proxy *theProxy, char *currentLine)
{
        DEBUG_PRINT("FUNCTION: getChunkedLine\n");
        if (currentLine[0] == 'T') {
                bool totalWord = true;
                char *word = "Transfer-Encoding: chunked";
                for (int i = 1; i < 26; i++) {
                        if (currentLine[i] != word[i]) {
                                totalWord = false;
                        }
                }
                //we have found the get header line
                if (totalWord) {
                        return true;
                }
        }
        return false;
}



/*
 * name:      removeAcceptEncoding
 * purpose:   removes the accept encoding line from the header so the server 
 *            does not send encoded data
 * arguments: the proxy instance, the slot in the table, the bucket index
 * returns:   none
 * effects:   none
 */
void removeAcceptEncoding(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: removeAcceptEncoding\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        char *currentLine;
        
        int currLineEnd = 0;
        int prevLineEnd = 0;
        while (currLineEnd < client->bufferSize) {
                currentLine = malloc(10000);
                prevLineEnd = currLineEnd;
                currLineEnd = readLine(client->readBuffer, currentLine, currLineEnd);
                if (checkAcceptEncodingLine(theProxy, currentLine)) {
                        int lineSize = currLineEnd - prevLineEnd;
                        char *newBuffer = malloc(client->bufferSize - lineSize + 1);
                        memcpy(newBuffer, client->readBuffer, prevLineEnd);
                        memcpy(newBuffer + prevLineEnd, client->readBuffer + 
                                currLineEnd, client->bufferSize - currLineEnd);
                        newBuffer[client->bufferSize - lineSize] = '\0';
                        // free(client->readBuffer);
                        client->readBuffer = newBuffer;
                        client->bufferSize = client->bufferSize - lineSize;
                        free(currentLine);
                        return;
                }
                free(currentLine);
        }
}


/*
 * name:      checkAcceptEncodingLine
 * purpose:   checks a provided line and sees if it is the accept encoding line
 * arguments: the proxy instance, the current line
 * returns:   true if the line is the accept encoding line, false otherwise
 * effects:   none
 */
bool checkAcceptEncodingLine(proxy *theProxy, char *currentLine)
{
        DEBUG_PRINT("FUNCTION: checkAcceptEncodingLine\n");
        if (currentLine[0] == 'A' || currentLine[0] == 'a') {
                bool totalWord1 = true;
                bool totalWord2 = true;
                bool totalWord3 = true;
                char *word1 = "Accept-Encoding: ";
                char *word2 = "Accept-encoding: ";
                char *word3 = "accept-encoding: ";
                for (int i = 1; i < 17; i++) {
                        if (currentLine[i] != word1[i]) {
                                totalWord1 = false;
                        }
                        if (currentLine[i] != word2[i]) {
                                totalWord2 = false;
                        }
                        if (currentLine[i] != word3[i]) {
                                totalWord3 = false;
                        }
                }
                //we have found the get header line
                if (totalWord1 || totalWord2 || totalWord3) {
                        return true;
                }
        }
        return false;
}




/******************************************************************************
*                           CHECKING FUNCTIONS
******************************************************************************/


/*
 * name:      checkFatalNullSSL
 * purpose:   checks if the given object is NULL and exits the program if so
 * arguments: the object to check
 * returns:   none
 * effects:   exits the program if the object is NULL
 */
void checkFatalNullSSL(void *object)
{
        if (object == NULL) {
                ERROR_PRINT("Fatal NULL Detected, program exiting\n");
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }
}


/*
 * name:      checkNullErrSSL
 * purpose:   checks if the given object is NULL and removes the client or 
 *            server if so
 * arguments: the proxy, slot, index, object to check, error number
 * returns:   true if an error was detected, false if not
 * effects:   removes the client or server if there was an error
 */
bool checkNullErrSSL(proxy *theProxy, int slot, int index, void *object, int i)
{
        if (object == NULL) {
                ERROR_PRINT("object is NULL at location %d\n", i);
                ERR_print_errors_fp(stderr);
                if (theProxy->clientTable[slot].slotArray[index].isClient) {
                        removeClient(theProxy, slot, index);
                }
                else {
                        removeServer(theProxy, slot, index);
                }
                return true;
        }

        return false;
}


/*
 * name:      checkNegErrSSL
 * purpose:   checks if the given object is 0 or -1 and removes the client or 
 *            server if so
 * arguments: the proxy, slot, index, value to check, error number
 * returns:   true if an error was detected, false if not
 * effects:   removes the client or server if there was an error
 */
bool checkNegErrSSL(proxy *theProxy, int slot, int index, int value, int i)
{
        if (value == 0) {
                ERROR_PRINT("value is 0 at location %d\n", i);
                ERR_print_errors_fp(stderr);
                if (theProxy->clientTable[slot].slotArray[index].isClient) {
                        removeClient(theProxy, slot, index);
                }
                else {
                        removeServer(theProxy, slot, index);
                }
                
                return true;
        }
        if (value < 0) {
                ERROR_PRINT("value is -1 at location %d\n", i);
                ERR_print_errors_fp(stderr);
                if (theProxy->clientTable[slot].slotArray[index].isClient) {
                        removeClient(theProxy, slot, index);
                }
                else {
                        removeServer(theProxy, slot, index);
                }
                return true;
        }

        return false;
}


/*
 * name:      checkNegOneErrSSL
 * purpose:   checks if the given object is -1 and removes the client or 
 *            server if so
 * arguments: the proxy, slot, index, value to check, error number
 * returns:   true if an error was detected, false if not
 * effects:   removes the client or server if there was an error
 */
bool checkNegOneErrSSL(proxy *theProxy, int slot, int index, int value, int i)
{
        if (value < 0) {
                ERROR_PRINT("value is -1 at location %d\n", i);
                ERR_print_errors_fp(stderr);
                if (theProxy->clientTable[slot].slotArray[index].isClient) {
                        removeClient(theProxy, slot, index);
                }
                else {
                        removeServer(theProxy, slot, index);
                }
                return true;
        }

        return false;
}


/*
 * name:      checkWantReadWrite
 * purpose:   checks if the return value indicates a want read / write
 * arguments: the proxy, slot, index, value to check, error number
 * returns:   true if want read / write, false if not
 * effects:   none
 */
bool checkWantReadWrite(proxy *theProxy, SSL *sslObj, int value, int i)
{
        if (value < 0) {
                int sslError = SSL_get_error(sslObj, value);
                if (sslError == SSL_ERROR_WANT_READ) {
                        ERROR_PRINT("SSL_ERROR_WANT_READ at location %d\n", i);
                        return true;
                } 
                if (sslError == SSL_ERROR_WANT_WRITE) {
                        ERROR_PRINT("SSL_ERROR_WANT_WRITE at location %d\n", i);
                        return true;
                }
        }
        return false;
}


/******************************************************************************
*                            RESET FUNCTIONS
******************************************************************************/


/*
 * name:      freeMITMFields
 * purpose:   frees the MITM related fields of a connection struct
 * arguments: the proxy, table slot, and bucket index
 * returns:   none
 * effects:   clears the MITM related fields
 */
void freeMITMFields(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: freeMITMFields\n");
        connectionInfo *conn = &theProxy->clientTable[slot].slotArray[index];
        if (theProxy->clientTable[slot].slotArray[index].mode == MITM) {
                if (conn->isClient && conn->connActive) {
                        if (conn->clientSSL != NULL) {
                                // SSL_free(conn->clientSSL);
                                conn->clientSSL = NULL;
                        }
                        if (conn->serverCert != NULL) {
                                X509_free(conn->serverCert);
                                conn->serverCert = NULL;
                        }
                        if (conn->serverKey != NULL) {
                                EVP_PKEY_free(conn->serverKey);
                                conn->serverKey = NULL;
                        }
                }
                else if (conn->connActive) {
                        if (conn->serverSSL != NULL) {
                                // SSL_free(conn->serverSSL);
                                conn->serverSSL = NULL;
                        }
                        if (conn->serverCtx != NULL) {
                                SSL_CTX_free(conn->serverCtx); 
                                conn->serverCtx = NULL;
                        }
                }
        }
}