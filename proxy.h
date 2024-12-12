/*****************************************************************************
 *
 *      proxy.h
 *      
 *      Isabel Muste (imuste01)
 *      Marti Zentmaier (mzentm01)
 * 
 *      11/10/2024
 *      
 *      CS 112 Final Project
 * 
 *      contains the function declarations for the entire proxy program as 
 *      well as the structs used to maintain data for the proxy
 *
 *
 *****************************************************************************/

#ifndef PROXY_H

#include "include.h"
#include "cache.h"



/*
 * name:      connectionInfo struct
 * purpose:   stores information about a client such as the socket descriptor,
 *            the last read message, etc.
 */
typedef struct {

        int clientSD;
        int serverSD; 
        bool isClient;
        bool mode;

        int bufferSize;
        int bufferRead;
        char *readBuffer;

        int headerSize;
        int headerRead;
        char *msgHeader;

        int contentSize;
        int contentRead;
        char *msgContent;

        int contentEncoding;
        bool chunkedContent;
        bool divAdded;

        bool connActive;
        unsigned long long timeAdded;

        char *serverURL;
        int serverPort;

        SSL *clientSSL;

        SSL_CTX *serverCtx;
        SSL *serverSSL;
        X509 *serverCert;
        EVP_PKEY *serverKey;

} connectionInfo;


/*
 * name:      cacheSlot struct
 * purpose:   stores an array of cacheElements for a specific hash table 
 *            bucket as well as the number of items in the array
 */
typedef struct {

        int numSlotItems;
        connectionInfo *slotArray;

} tableSlot;



/*
 * name:      proxy struct
 * purpose:   stores information about the proxy such as the listening port, 
 *            active clients, and the client list
 */
typedef struct {

        int listenSD;
        int portNumber;
        fd_set activeFDSet;
        fd_set readFDSet;
        int maxFD;

        int proxyMode;

        tableSlot *clientTable;
        cacheInfo *theCache;

        int tableSize;
        int numClients;

        SSL_CTX *clientCtx;
        X509 *rootCert;
        EVP_PKEY *rootKey;

        char *connSolution;
        char *connGuess;
        char *LLMResponse;
        
} proxy;


/******************************************************************************
*                       PROXY FUNCTION DECLARATIONS
******************************************************************************/
proxy *newProxy(int port, cacheInfo *theCache, int mode);
void proxyListening(proxy *theProxy);
void selectConnections(proxy *theProxy, struct sockaddr_in clientAddress);


// Connection Processing
void processConnection(proxy *theProxy, int SD);
void processClient(proxy *theProxy, int slot, int clientSD);
void setupCommunication(proxy *theProxy, int slot, int index);
void facilitateCommunication(proxy *theProxy, int slot, int index);


// Initial Connect Handling
bool processConnectRequest(proxy *theProxy, int slot, int index);
bool readConnectRequest(proxy *theProxy, int slot, int index);
bool sendConnEstablished(proxy *theProxy, int slot, int index); 


// Parsing Functions
void parseConnectHeader(proxy *theProxy, int slot, int index);
int readLine(char *messageBuffer, char *lineBuffer, int totalRead);
char *getConnectLine(proxy *theProxy, char *currentLine);
char *getHostLine(proxy *theProxy, char *currentLine);
char *getHostURL(proxy *theProxy, char *hostMsg);
int getServerPort(proxy *theProxy, char *connectLine, char *hostLine);
int getPortFromLine(proxy *theProxy, char *currLine);


// Checking Functions
bool checkConnectField(proxy *theProxy, int slot, int index);
bool checkFullConnectHeader(proxy *theProxy, int slot, int index);
void checkFatalNegOne(int returnVal);
void checkFatalNull(void *object);


// Hashing Function
unsigned int hashTableKey(proxy *theProxy, int hashKey);
bool checkTableExpansion(proxy *theProxy);
void expandTable(proxy *theProxy);


// Helper Functions
void createSocket(proxy *theProxy);
bool getClientAtSlot(proxy *theProxy, int slot, int *index, int SD);
bool getServerAtSlot(proxy *theProxy, int slot, int *index, int SD);
void setConnectionMode(proxy *theProxy, int slot, int index);
void setSDNonBlocking(int socketSD);
void initializeBucketSlots(tableSlot *tableSlot, int slot, bool mode);


// Reset Functions
void removeClient(proxy *theProxy, int slot, int index);
void removeServer(proxy *theProxy, int slot, int index);
void freeTableSlot(proxy *theProxy, int slot, int index);
void resetClientMaxFD(proxy *theProxy, int slot, int index);
void resetServerMaxFD(proxy *theProxy, int slot, int index);




/******************************************************************************
*                        MITM FUNCTION DECLARATIONS
******************************************************************************/
void initializeClientContext(proxy *theProxy);
void initializeRootCert(proxy *theProxy);


// SSL Client / Server Setup
bool setupServerCertificate(proxy *theProxy, int slot, int index);
bool addSubjectAltName(X509 *cert, const char *domain);
bool sendCertificateToClient(proxy *theProxy, int slot, int index);
bool connectToServer(proxy *theProxy, int slot, int index);
void connectServerSSL(proxy *theProxy, int slot, int index);
bool populateServerStructSSL(proxy *theProxy, connectionInfo *client);


// SSL Client To Server Relaying
void relayClientToServerSSL(proxy *theProxy, int slot, int index);
int readFromClientSSL(proxy *theProxy, int slot, int index, SSL *clientSSL, 
        char *readBuffer, int bufferSize);
int writeToServerSSL(proxy *theProxy, int slot, int index, SSL *serverSSL, 
        char *readBuffer, int readReturn);


// SSL Server To Client Relaying
void relayServerToClientSSL(proxy *theProxy, int slot, int index);
int readFromServerSSL(proxy *theProxy, int slot, int index, SSL *serverSSL, 
        char *readBuffer, int bufferSize);
int writeToClientSSL(proxy *theProxy, int slot, int index, SSL *clientSSL, 
        char *readBuffer, int readReturn);


// Populate Client Header / Content Fields
bool handleClientConnectionsData(proxy *theProxy, int slot, int index);
bool populateClientRequestFields(proxy *theProxy, int slot, int index);
bool populateClientHeaderField(proxy *theProxy, int slot, int index);
bool populateClientContentField(proxy *theProxy, int slot, int index);
bool getConnectionGuess(proxy *theProxy, int slot, int index);


// Populate Server Header / Content Fields
bool handleServerConnectionsData(proxy *theProxy, int slot, int index);
bool populateServerResponseFields(proxy *theProxy, int slot, int index);
bool populateServerHeaderField(proxy *theProxy, int slot, int index);
bool populateServerContentField(proxy *theProxy, int slot, int index);
bool readContentChunks(proxy *theProxy, int slot, int index);
bool readContentStream(proxy *theProxy, int slot, int index);
bool getConnectionSolution(proxy *theProxy, int slot, int index);
bool addDivToContent(proxy *theProxy, int slot, int index);
bool addEmptyDivToContent(proxy *theProxy, int slot, int index);
bool addDivToBuffer(proxy *theProxy, int slot, int index);


// Header / Content Parsing Functions
int checkEndDelimiter(proxy *theProxy, int slot, int index, char *buffer, 
        int size);

void setContentLength(proxy *theProxy, int slot, int index, int length);
void setContentEncoding(proxy *theProxy, int slot, int index, char *buffer, 
        int bufferSize);
char *getContentEncodingLine(proxy *theProxy, char *currentLine);
void getContentLength(proxy *theProxy, int slot, int index, char *buffer, 
        int bufferSize);
char *getLengthLine(proxy *theProxy, char *currentLine);
bool getChunkedLine(proxy *theProxy, char *currentLine);
void removeAcceptEncoding(proxy *theProxy, int slot, int index);
bool checkAcceptEncodingLine(proxy *theProxy, char *currentLine);


// Error Checking Functions
void checkFatalNullSSL(void *object);
bool checkNullErrSSL(proxy *theProxy, int slot, int index, void *object, int i);
bool checkNegErrSSL(proxy *theProxy, int slot, int index, int value, int i);
bool checkNegOneErrSSL(proxy *theProxy, int slot, int index, int value, int i);
bool checkWantReadWrite(proxy *theProxy, SSL *sslObj, int value, int i);


// Reset Functions
void freeMITMFields(proxy *theProxy, int slot, int index);





/******************************************************************************
*                       TUNNEL FUNCTION DECLARATIONS
******************************************************************************/
void setupTunnelToServer(proxy *theProxy, int slot, int index);
void populateServerStruct(proxy *theProxy, int serverSD, connectionInfo *client);
void relayClientToServer(proxy *theProxy, int slot, int index);
void relayServerToClient(proxy *theProxy, int slot, int index);




/******************************************************************************
*                       LLM FUNCTION DECLARATIONS
******************************************************************************/
void initializeCategories(proxy *thisProxy);
void makeLLMCall(proxy *theProxy);
void extractResponse(proxy *theProxy, char *response, char **cat1, char **cat2, 
        char **cat3, char **cat4);
void populateFinalDiv(proxy *theProxy, char *cat1, char *cat2, char *cat3, 
        char *cat4);
size_t writeCallbackLLM(void *ptr, size_t size, size_t nmemb, char *data);
void makeProxyRequestLLM(char *model, char *system, char *query, char *response);
void formatConnectionsSolution(proxy *theProxy, char *connSol);
bool checkHintRegeneration(proxy *theProxy, int slot, int index);
void sendNewlyGeneratedHints(proxy *theProxy, int slot, int index);


#endif