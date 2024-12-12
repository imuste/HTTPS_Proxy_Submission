/*****************************************************************************
 *
 *      proxy.c
 *      
 *      Isabel Muste (imuste01)
 *      Marti Zentmaier (mzentm01)
 * 
 *      11/10/2024
 *      
 *      CS 112 Final Project
 * 
 *      Contains the proxy logic which runs the client and server communication 
 *      as well as providing the paths to the MITM or Tunnel modes
 *      
 *
 *****************************************************************************/

#include "proxy.h"
#include "logging.h"

#define TUNNEL 0
#define MITM 1



/*****************************************************************************
*                          PROXY SETUP / LISTENING
******************************************************************************/


/*
 * name:      newProxy
 * purpose:   allocates memory for a new proxy instance
 * arguments: the proxy port number specified by the user
 * returns:   the proxy instance
 * effects:   none
 */
proxy *newProxy(int port, cacheInfo *theCache, int mode)
{
        DEBUG_PRINT("FUNCTION: newProxy\n");
        int tabSize = 200;

        proxy *theProxy = malloc(sizeof(proxy));
        checkFatalNull(theProxy);

        theProxy->clientTable = (tableSlot *)malloc(tabSize * sizeof(tableSlot));
        checkFatalNull(theProxy->clientTable);

        for (int i = 0; i < tabSize; i++) {
                theProxy->clientTable[i].numSlotItems = 0;

                theProxy->clientTable[i].slotArray = 
                        (connectionInfo *)malloc(10 * sizeof(connectionInfo));
                checkFatalNull(theProxy->clientTable[i].slotArray);

                for (int j = 0; j < 10; j++) {
                        theProxy->clientTable[i].slotArray[j].clientSD = -1;
                        theProxy->clientTable[i].slotArray[j].serverSD = -1;
                        theProxy->clientTable[i].slotArray[j].isClient = false;
                        theProxy->clientTable[i].slotArray[j].mode = mode;

                        theProxy->clientTable[i].slotArray[j].bufferSize = -1;
                        theProxy->clientTable[i].slotArray[j].bufferRead = 0;
                        theProxy->clientTable[i].slotArray[j].readBuffer = NULL;

                        theProxy->clientTable[i].slotArray[j].headerSize = -1;
                        theProxy->clientTable[i].slotArray[j].headerRead = 0;
                        theProxy->clientTable[i].slotArray[j].msgHeader = NULL;
                        
                        theProxy->clientTable[i].slotArray[j].contentSize = -1;
                        theProxy->clientTable[i].slotArray[j].contentRead = 0;
                        theProxy->clientTable[i].slotArray[j].msgContent = NULL;

                        theProxy->clientTable[i].slotArray[j].contentEncoding = -1;
                        theProxy->clientTable[i].slotArray[j].chunkedContent = false;
                        theProxy->clientTable[i].slotArray[j].divAdded = false;

                        theProxy->clientTable[i].slotArray[j].connActive = false;
                        theProxy->clientTable[i].slotArray[j].timeAdded = -1;

                        theProxy->clientTable[i].slotArray[j].serverURL = NULL;
                        theProxy->clientTable[i].slotArray[j].serverPort = -1;

                        theProxy->clientTable[i].slotArray[j].clientSSL = NULL;

                        theProxy->clientTable[i].slotArray[j].serverCtx = NULL;
                        theProxy->clientTable[i].slotArray[j].serverSSL = NULL;
                        theProxy->clientTable[i].slotArray[j].serverCert = NULL;
                        theProxy->clientTable[i].slotArray[j].serverKey = NULL;
                }
        }

        theProxy->listenSD = -1;
        theProxy->portNumber = port;
        theProxy->maxFD = -1;
        theProxy->proxyMode = mode;
        theProxy->theCache = theCache;
        theProxy->tableSize = tabSize;
        theProxy->numClients = 0;
        theProxy->clientCtx = NULL;
        theProxy->connSolution = NULL;
        theProxy->connGuess = NULL;
        theProxy->LLMResponse = NULL;
        
        return theProxy;
}


/*
 * name:      proxyListening
 * purpose:   listens for incoming clients and processes their requests either 
 *            by sending them to the corresponding server or by getting the 
 *            response from the cache
 * arguments: the proxy instance
 * returns:   none
 * effects:   none
 */
void proxyListening(proxy *theProxy)
{
        DEBUG_PRINT("FUNCTION: proxyListening\n");
        //setup the server socket
        createSocket(theProxy);

        //listen for incoming connections
        int returnVal = listen(theProxy->listenSD, 500);
        checkFatalNegOne(returnVal);

        // set timeout value for select call
        struct timeval timing;
        timing.tv_sec = 10;
        timing.tv_usec = 0;
        
        struct sockaddr_in clientAddress;
        socklen_t clientAddressLength;
        FD_ZERO(&theProxy->activeFDSet);
        FD_ZERO(&theProxy->readFDSet);
        FD_SET(theProxy->listenSD, &theProxy->activeFDSet);   
        theProxy->maxFD = theProxy->listenSD;    

        while (true) {
                selectConnections(theProxy, clientAddress);
        }
        close(theProxy->listenSD);
}


/*
 * name:      selectConnections
 * purpose:   get client requests using the select calls
 * arguments: the proxy instance, the clientAddress, the maximum FD
 * returns:   none
 * effects:   none
 */
void selectConnections(proxy *theProxy, struct sockaddr_in clientAddress)
{
        DEBUG_PRINT("FUNCTION: selectConnections\n");
        theProxy->readFDSet = theProxy->activeFDSet;
        int returnVal = select(theProxy->maxFD + 1, &theProxy->readFDSet, NULL, 
                        NULL, NULL);
        if (returnVal == 0 || returnVal == -1) {
                return;
        }

        if (FD_ISSET(theProxy->listenSD, &theProxy->readFDSet)) {
                socklen_t clientAddressLength = sizeof(clientAddress);
                int clientSD = accept(theProxy->listenSD, 
                        (struct sockaddr *)&clientAddress, 
                        &clientAddressLength);
                if (clientSD == -1) {
                        return;
                }
                FD_SET(clientSD, &theProxy->activeFDSet);
                if (clientSD > theProxy->maxFD) {
                        theProxy->maxFD = clientSD;
                }
                return;
        }
        for (int i = 0; i <= theProxy->maxFD; i++) {
                if (FD_ISSET(i, &theProxy->readFDSet)) {
                        processConnection(theProxy, i);
                        return;
                }
        }
}




/*****************************************************************************
*                           PROCESS CONNECTIONS
******************************************************************************/


/*
 * name:      processConnection
 * purpose:   checks the type of connection (client / server) and processes it 
 *            accordingly
 * arguments: the proxy instance, the socket descriptor
 * returns:   none
 * effects:   none
 */
void processConnection(proxy *theProxy, int SD)
{       
        DEBUG_PRINT("FUNCTION: processConnection\n");
        int index = -1;
        int slot = hashTableKey(theProxy, SD);

        if (getServerAtSlot(theProxy, slot, &index, SD)) {
                facilitateCommunication(theProxy, slot, index);
        }
        else {
                checkTableExpansion(theProxy);
                processClient(theProxy, slot, SD);
        }
}



/*
 * name:      processClient
 * purpose:   processes a client that is either new or existing
 * arguments: the proxy instance, slot in the table of the client, the socket 
 *            descriptor
 * returns:   none
 * effects:   none
 */
void processClient(proxy *theProxy, int slot, int clientSD)
{       
        DEBUG_PRINT("FUNCTION: processClient\n");
        int index = -1;
        bool existClient = getClientAtSlot(theProxy, slot, &index, clientSD);
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        // the client is new, set SD, increment numClients and slotItems
        if (!existClient) {
                client->clientSD = clientSD;
                client->isClient = true;
                theProxy->numClients++;
                theProxy->clientTable[slot].numSlotItems++;
                if (processConnectRequest(theProxy, slot, index)) {
                        setupCommunication(theProxy, slot, index);
                }
        }
        else {
                if (!client->connActive) {
                        if (processConnectRequest(theProxy, slot, index)) {
                                setupCommunication(theProxy, slot, index);
                        }
                        return;
                }
                facilitateCommunication(theProxy, slot, index);
        }
}


/*
 * name:      setupCommunication
 * purpose:   does the communication setup for both the tunnel and MITM mode
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
void setupCommunication(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: setupCommunication\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        if (!sendConnEstablished(theProxy, slot, index)) {
                return;
        }
        if (client->mode == TUNNEL) {
                setupTunnelToServer(theProxy, slot, index);
        }
        else {
                if (setupServerCertificate(theProxy, slot, index)
                && sendCertificateToClient(theProxy, slot, index)
                && connectToServer(theProxy, slot, index)) {
                        connectServerSSL(theProxy, slot, index);
                }
        }

        if (client->msgHeader != NULL) {
                free(client->msgHeader);
                client->msgHeader = NULL;
        }
        client->headerSize = -1;
        client->headerRead = 0;
}



/*
 * name:      facilitateCommunication
 * purpose:   calls the correct functions to relay information between 
 *            servers and clients
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
void facilitateCommunication(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: facilitateCommunication\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        if (client->mode == TUNNEL) {
                if (client->isClient) {
                        relayClientToServer(theProxy, slot, index);
                }
                else {
                        relayServerToClient(theProxy, slot, index);
                }
        }
        else {
                if (client->isClient) {
                        relayClientToServerSSL(theProxy, slot, index);
                }
                else {
                        relayServerToClientSSL(theProxy, slot, index);
                }
        }       
}





/*****************************************************************************
*                        INITIAL CONNECT HANDLING
******************************************************************************/


/*
 * name:      processConnectRequest
 * purpose:   processes the connect request and checks if it has fully arrived
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
bool processConnectRequest(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: processConnectRequest\n");
        // either read the new connect request, or rest of the previous one
        if (!readConnectRequest(theProxy, slot, index)) {
                removeClient(theProxy, slot, index);
                return false;
        }

        // check if the connect request is complete
        if (!checkFullConnectHeader(theProxy, slot, index)) {
                removeClient(theProxy, slot, index);
                return false;
        }

        // check if the connect field is valid, otherwise close the connection
        if (!checkConnectField(theProxy, slot, index)) {
                if (checkHintRegeneration(theProxy, slot, index)) {
                        sendNewlyGeneratedHints(theProxy, slot, index);
                        return false;
                }
                removeClient(theProxy, slot, index);
                return false;
        }
        parseConnectHeader(theProxy, slot, index);
        // setConnectionMode(theProxy, slot, index);

        return true;
}


/*
 * name:      readConnectRequest
 * purpose:   performs a read call to get the connect request header
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
bool readConnectRequest(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: readConnectRequest\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        int bufferSize = 2048;
        char *readBuffer = malloc(bufferSize + 1);
        checkFatalNull(readBuffer);

        int returnVal = read(client->clientSD, readBuffer, bufferSize);
        if (returnVal == 0 || returnVal == -1) {
                free(readBuffer);
                return false;
        }
        readBuffer[returnVal] = '\0';

        // allocate memory for the msgHeader
        char *connectHeader = malloc(returnVal + client->headerRead + 1);
        checkFatalNull(connectHeader);

        // copy whatever was previously read
        if ((client->headerRead > 0) && (client->msgHeader != NULL)) {
                memcpy(connectHeader, client->msgHeader, client->headerRead);
                free(client->msgHeader);
        }
        
        // copy the new data to the connectHeader
        memcpy(connectHeader + client->headerRead, readBuffer, returnVal);

        client->msgHeader = connectHeader;
        client->headerRead += returnVal;
        client->msgHeader[client->headerRead] = '\0';
        free(readBuffer);
        return true;
}


/*
 * name:      sendConnEstablished
 * purpose:   sends a connection established message to the client indicating 
 *            that the connection request was received
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
bool sendConnEstablished(proxy *theProxy, int slot, int index) 
{
        DEBUG_PRINT("FUNCTION: sendConnEstablished\n");
        char *response = "HTTP/1.1 200 Connection Established\r\n\r\n"; 

        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        int clientSD = client->clientSD; 

        int returnVal = write(clientSD, response, strlen(response));
        if (returnVal == 0 || returnVal == -1) {
                removeClient(theProxy, slot, index);
                return false;
        }

        return true;
}



/*****************************************************************************
*                            PARSING FUNCTIONS
******************************************************************************/


/*
 * name:      parseConnectHeader
 * purpose:   process the connect header to find the host and port number
 * arguments: the proxy, the client table bucket, the bucket index
 * returns:   none
 * effects:   none
 */
void parseConnectHeader(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: parseConnectHeader\n");
        int messageLength = theProxy->clientTable[slot].slotArray[index].headerSize;
        char *clientRequest = theProxy->clientTable[slot].slotArray[index].msgHeader;
        char *currentLine;
        char *hostLine = NULL;
        char *connectLine = NULL;

        int totalRead = 0;
        while (totalRead < messageLength) {
                currentLine = malloc(500);
                checkFatalNull(currentLine);
                totalRead = readLine(clientRequest, currentLine, totalRead);
                
                if (connectLine == NULL) {
                        connectLine = getConnectLine(theProxy, currentLine);
                }
                hostLine = getHostLine(theProxy, currentLine);
                if (hostLine != NULL) {
                        free(currentLine);
                        break;
                }
                free(currentLine);
        }

        theProxy->clientTable[slot].slotArray[index].serverURL = 
                getHostURL(theProxy, hostLine);

        //extract the server port
        int serverPort = getServerPort(theProxy, hostLine, connectLine);
        theProxy->clientTable[slot].slotArray[index].serverPort = serverPort;
}



/*
 * name:      readLine
 * purpose:   reads a line from the message and stores it in the lineBuffer
 * arguments: file descriptor, buffer, total bytes read
 * returns:   number of total bytes read
 * effects:   none
 */
int readLine(char *messageBuffer, char *lineBuffer, int totalRead)
{
        DEBUG_PRINT("FUNCTION: readLine\n");
        int bytesRead = 0;

        // read one char at a time until we reach EOF or \r\n
        while ((messageBuffer[totalRead + bytesRead] != '\n') 
        && (messageBuffer[totalRead + bytesRead] != '\0')) {
                if ((messageBuffer[totalRead + bytesRead] == '\r') 
                && (messageBuffer[totalRead + bytesRead + 1] == '\n')){
                        break;   
                }
                lineBuffer[bytesRead] = messageBuffer[totalRead + bytesRead];
                bytesRead++;
                
        }

        lineBuffer[bytesRead] = '\0';
        return totalRead + bytesRead + 2;
}



/*
 * name:      getConnectLine
 * purpose:   indicates if the current line is the connect line
 * arguments: the proxy, the current line
 * returns:   the connect line, or NULL if it was not found
 * effects:   none
 */
char *getConnectLine(proxy *theProxy, char *currentLine)
{
        DEBUG_PRINT("FUNCTION: getConnectLine\n");
        char *connectLine = NULL;

        if (currentLine[0] == 'C') {
                bool totalWord = true;
                char *word = "CONNECT ";
                for (int i = 1; i < 8; i++) {
                        if (currentLine[i] != word[i]) {
                                totalWord = false;
                        }
                }
                //we have found the get header line
                if (totalWord) {
                        connectLine = malloc(strlen(currentLine) + 1);
                        checkFatalNull(connectLine);
                        strcpy(connectLine, currentLine);
                }
        }
        return connectLine;
}


/*
 * name:      getHostLine
 * purpose:   indicates if the current line is the host line
 * arguments: the proxy, the current line
 * returns:   the host line, or NULL if it was not found
 * effects:   none
 */
char *getHostLine(proxy *theProxy, char *currentLine)
{
        DEBUG_PRINT("FUNCTION: getHostLine\n");
        char *hostLine = NULL; 

        if (currentLine[0] == 'H') {
                bool totalWord = true;
                char *word = "Host: ";
                for (int i = 1; i < 6; i++) {
                        if (currentLine[i] != word[i]) {
                                totalWord = false;
                        }
                }
                //we have found the get header line
                if (totalWord) {
                        hostLine = malloc(strlen(currentLine) + 1);
                        checkFatalNull(hostLine);
                        strcpy(hostLine, currentLine);
                }
        }
        return hostLine;
}


/*
 * name:      getHostURL
 * purpose:   gets the host URL without the port number
 * arguments: the proxy
 * returns:   the host URL
 * effects:   none
 */
char *getHostURL(proxy *theProxy, char *hostMsg)
{
        DEBUG_PRINT("FUNCTION: getHostURL\n");
        char *URL = malloc(150);
        checkFatalNull(URL);
        int ogLineCtr = 6;
        int URLctr = 0;

        while (hostMsg[ogLineCtr] != ' ' && hostMsg[ogLineCtr] != '\n' &&
                hostMsg[ogLineCtr] != '\r' && hostMsg[ogLineCtr] != '\0'
                && hostMsg[ogLineCtr] != ':') {

                URL[URLctr] = hostMsg[ogLineCtr];
                URLctr++;
                ogLineCtr++;
        }
        URL[URLctr] = '\0';

        return URL;
}


/*
 * name:      getServerPort
 * purpose:   gets the appropriate server port from the connect or host line
 * arguments: the proxy, the connect line, the host line
 * returns:   the server port or 80 if no port was found
 * effects:   none
 */
int getServerPort(proxy *theProxy, char *connectLine, char *hostLine)
{
        DEBUG_PRINT("FUNCTION: getServerPort\n");
        int serverPort = -1;

        int serverPort1 = getPortFromLine(theProxy, hostLine);
        int serverPort2 = getPortFromLine(theProxy, connectLine);
        if (serverPort1 == -1 && serverPort2 == -1) {
                serverPort = 80;
        }
        else if (serverPort1 == -1 && serverPort2 != -1) {
                serverPort = serverPort2;
        }
        else if (serverPort1 != -1 && serverPort2 == -1) {
                serverPort = serverPort1;
        }
        else {
                serverPort = serverPort2;
        }

        return serverPort;
}


/*
 * name:      getPortFromLine
 * purpose:   extracts a server port from the given line if one exists
 * arguments: the proxy, the line
 * returns:   the server port or -1 if no port was found
 * effects:   none
 */
int getPortFromLine(proxy *theProxy, char *currLine)
{
        DEBUG_PRINT("FUNCTION: getPortFromLine\n");
        int bytesRead = 5;
        bool portFound = false;
        char *portStr = calloc(100, sizeof(char));
        int portCtr = 0;
        int portNumber = -1;

        //read through the entire line
        while ((currLine[bytesRead] != '\0')) {
                //find server port deliminator
                if (currLine[bytesRead] == ':') {
                        portFound = true;
                }
                else if (portFound) {
                        portStr[portCtr] = currLine[bytesRead];
                        portCtr++;
                }
                bytesRead++;
        }
        portStr[portCtr] = '\0';

        if (portFound) {
                portNumber = atoi(portStr);
        }

        free(portStr);
        return portNumber;
}






/*****************************************************************************
*                            CHECKING FUNCTIONS
******************************************************************************/


/*
 * name:      checkIfConnect
 * purpose:   checks the first line of the client request is a CONNECT request
 * arguments: the proxy instance, the slot in the list of the client
 * returns:   true if the message contains a connect request, false if not
 * effects:   none
 */
bool checkConnectField(proxy *theProxy, int slot, int index) 
{
        DEBUG_PRINT("FUNCTION: checkConnectField\n");
        if ((strncmp(theProxy->clientTable[slot].slotArray[index].msgHeader, 
                "CONNECT", 7)) == 0) {
                return true;
        }
        return false;
}


/*
 * name:      checkFullConnectHeader
 * purpose:   checks if the full CONNECT header was received
 * arguments: the proxy instance, the table bucket, the bucket index
 * returns:   true if the full header was received, false if not
 * effects:   none
 */
bool checkFullConnectHeader(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: checkFullConnectHeader\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        //check if we have found end of header delimiter, if so client is active
        char *endOfReq = "\r\n\r\n";
        char *header = client->msgHeader;
        char *endStr = strstr(header, endOfReq);
        
        // request is not complete, so we can't do anything yet
        if (endStr == NULL) {
                return false;
        }

        // the request is complete, so the client is active and we can continue
        client->headerSize = endStr - header + 4;
        client->connActive = true;
        client->msgHeader[client->headerSize] = '\0';
        return true;
}



/*
 * name:      checkFatalNegOne
 * purpose:   checks the return value of a function and exits the program if 
 *            it is -1
 * arguments: the return value
 * returns:   none
 * effects:   none
 */
void checkFatalNegOne(int returnVal)
{
        if (returnVal < 0) {
                ERROR_PRINT("Something went wrong, program exiting\n");
                exit(EXIT_FAILURE);
        }
}


/*
 * name:      checkFatalNull
 * purpose:   checks an pointer to allocated memory and exits the program if 
 *            it is NULL
 * arguments: the return value
 * returns:   none
 * effects:   none
 */
void checkFatalNull(void *object)
{
        if (object == NULL) {
                ERROR_PRINT("Memory could not be allocated, program exiting\n");
                exit(EXIT_FAILURE);
        }
}




/******************************************************************************
*                       HASHING / EXPANDING FUNCTIONS
******************************************************************************/

/*
 * name:      hash
 * purpose:   hashes the key of an item
 * arguments: cache instance, the key to hash
 * returns:   the hash of the item key
 * effects:   none
 */
unsigned int hashTableKey(proxy *theProxy, int hashKey)
{
        unsigned int hash_output;
        MurmurHash3_x86_32(&hashKey, sizeof(hashKey), 42, &hash_output);
        return hash_output % theProxy->tableSize;
}


/*
 * name:      checkTableExpansion
 * purpose:   checks the load factor of the table to see if expansion is 
 *            necessary but doesn't expand if the table size is already 3000
 * arguments: cache instance
 * returns:   true if the table was expanded, false if no expansion is possible
 * effects:   none
 */
bool checkTableExpansion(proxy *theProxy)
{       
        if (theProxy->tableSize >= 3000) {
                return false;
        }

        double loadFactor = (double)theProxy->numClients / 
                (double)theProxy->tableSize;

        if (loadFactor >= 0.75) {
                expandTable(theProxy);
        }

        return true;
}


/*
 * name:      expandTable
 * purpose:   doubles the hash table if the loadfactor of 0.75 was exceeded
 * arguments: cache instance
 * returns:   none
 * effects:   none
 */
void expandTable(proxy *theProxy)
{
        DEBUG_PRINT("FUNCTION: expandTable\n");
        int oldSize = theProxy->tableSize;
        int newSize = (oldSize * 2) + 2;
        tableSlot *newTable = (tableSlot *)malloc(newSize * sizeof(tableSlot));
        checkFatalNull(newTable);

        for (int i = 0; i < newSize; i++) {
                newTable[i].numSlotItems = 0;
                newTable[i].slotArray = 
                        (connectionInfo *)malloc(10 * sizeof(connectionInfo));
                checkFatalNull(newTable[i].slotArray);
                initializeBucketSlots(newTable, i, theProxy->proxyMode);
        }
        theProxy->tableSize = newSize;

        // copy over all elements from the old table to the new table
        // each element is rehashed before being copied
        for (int i = 0; i < oldSize; i++) {
                for (int j = 0; j < theProxy->clientTable[i].numSlotItems; j++) {
                        int slot = -1;
                        if (theProxy->clientTable[i].slotArray[j].isClient) {
                                slot = hashTableKey(theProxy, 
                                theProxy->clientTable[i].slotArray[j].clientSD);
                        }
                        else {
                                slot = hashTableKey(theProxy, 
                                theProxy->clientTable[i].slotArray[j].serverSD);
                        }
                        int items = newTable[slot].numSlotItems;
                        newTable[slot].slotArray[items] = 
                                theProxy->clientTable[i].slotArray[j];
                        newTable[slot].numSlotItems++;
                }
        }

        // free the old table
        for (int i = 0; i < oldSize; i++) {
                free(theProxy->clientTable[i].slotArray);
        }
        free(theProxy->clientTable);
        theProxy->clientTable = newTable;
}






/*****************************************************************************
*                            HELPER FUNCTIONS
******************************************************************************/


/*
 * name:      createSocket
 * purpose:   sets up the server socket connection
 * arguments: the server instance
 * returns:   none
 * effects:   populates the listenSD field of the server instance
 */
void createSocket(proxy *theProxy)
{
        DEBUG_PRINT("FUNCTION: createSocket\n");
        //socket setup
        struct sockaddr_in serverAddress;
        socklen_t serverAddressLength;
        int listenSD = socket(AF_INET, SOCK_STREAM, 0);
        checkFatalNegOne(listenSD);
        theProxy->listenSD = listenSD;

        //ensure to close the socket and port after termination
        int opt = 1;
        int returnVal = setsockopt(listenSD, SOL_SOCKET, SO_REUSEADDR, &opt, 
                        sizeof(opt));
        checkFatalNegOne(returnVal);

        //setup to bind the socket to port specified port and any IP address
        //this is the setup specifying the Proxy info
        memset(&serverAddress, 0, sizeof(struct sockaddr_in));
        serverAddress.sin_family = AF_INET;
        // serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
        serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
        serverAddress.sin_port = htons(theProxy->portNumber);
        returnVal = bind(listenSD, (struct sockaddr *)&serverAddress, 
                        sizeof(struct sockaddr_in));
        checkFatalNegOne(returnVal);
}


/*
 * name:      getClientAtSlot
 * purpose:   finds the client at the given hash bucket and returns the 
 *            bucket's index. If the client is not present, returns the next 
 *            available slot
 * arguments: the proxy instance, the client bucket, reference to the slot, 
 *            client socket descriptor
 * returns:   true if the client was found, false otherwise
 * effects:   none
 */
bool getClientAtSlot(proxy *theProxy, int slot, int *index, int SD)
{
        DEBUG_PRINT("FUNCTION: getClientAtSlot\n");
        // try to find the client in the bucket
        int slotItems = theProxy->clientTable[slot].numSlotItems;
        for (int i = 0; i < slotItems; i++) {
                connectionInfo client = theProxy->clientTable[slot].slotArray[i];
                if (client.clientSD == SD) {
                        *index = i;               
                        return true;
                }
        }

        // client wasn't found, so set it's slotIndex to the next free space
        *index = slotItems;
        return false;
}


/*
 * name:      getServerAtSlot
 * purpose:   finds the server at the given hash bucket and returns the 
 *            bucket's index
 * arguments: the proxy instance, the server bucket, reference to the slot, 
 *            server socket descriptor
 * returns:   true if the server was found, false otherwise
 * effects:   none
 */
bool getServerAtSlot(proxy *theProxy, int slot, int *index, int SD)
{
        DEBUG_PRINT("FUNCTION: getServerAtSlot\n");
        int slotItems = theProxy->clientTable[slot].numSlotItems;
        for (int i = 0; i < slotItems; i++) {
                connectionInfo server = theProxy->clientTable[slot].slotArray[i];
                if ((server.serverSD == SD) && (!server.isClient)) {
                        *index = i;
                        return true;
                }
        }

        return false;
}



/*
 * name:      setConnectionMode
 * purpose:   sets the connection mode for a slot to tunnel based on the URL
 * arguments: the bucket slot, the bucket, the slot of the bucket
 * returns:   none
 * effects:   none
 */
void setConnectionMode(proxy *theProxy, int slot, int index)
{       
        DEBUG_PRINT("FUNCTION: setConnectionMode\n");
        if (theProxy->proxyMode == MITM) {

                char *icloudInd = "icloud";
                char *playInd = "play";
                char *apiInd = "api";
                char *URL = theProxy->clientTable[slot].slotArray[index].serverURL;
                
                // this host is not an icloud host, so return
                char *endStr = strstr(URL, icloudInd);
                if (endStr != NULL) {
                        theProxy->clientTable[slot].slotArray[index].mode = TUNNEL;
                        return;
                }
                char *endStr1 = strstr(URL, playInd);
                if (endStr1 != NULL) {
                        theProxy->clientTable[slot].slotArray[index].mode = TUNNEL;
                        return;
                }
                char *endStr2 = strstr(URL, apiInd);
                if (endStr2 != NULL) {
                        theProxy->clientTable[slot].slotArray[index].mode = TUNNEL;
                        return;
                }
        }
}


void setSDNonBlocking(int socketSD)
{
        int flags = fcntl(socketSD, F_GETFL, 0);
	int returnVal = fcntl(socketSD, F_SETFL, flags | O_NONBLOCK);
        if (returnVal < 0) {
                ERROR_PRINT("Failed to set non-blocking SD\n");
        }
}


/*
 * name:      initializeBucketSlots
 * purpose:   initializes all the slots of a bucket in the hash table
 * arguments: the bucket slot, the slot number, the proxy mode
 * returns:   none
 * effects:   none
 */
void initializeBucketSlots(tableSlot *tableSlot, int slot, bool mode)
{
        DEBUG_PRINT("FUNCTION: initializeBucketSlots\n");
        for (int j = 0; j < 10; j++) {
                connectionInfo *conn = &tableSlot[slot].slotArray[j];

                conn->clientSD = -1;
                conn->serverSD = -1;
                conn->isClient = false;
                conn->mode = mode;

                conn->bufferSize = -1;
                conn->bufferRead = 0;
                conn->readBuffer = NULL;

                conn->headerSize = -1;
                conn->headerRead = 0;
                conn->msgHeader = NULL;
                
                conn->contentSize = -1;
                conn->contentRead = 0;
                conn->msgContent = NULL;

                conn->contentEncoding = -1;
                conn->chunkedContent = false;
                conn->divAdded = false;

                conn->connActive = false;
                conn->timeAdded = -1;

                conn->serverURL = NULL;
                conn->serverPort = -1;

                conn->clientSSL = NULL;

                conn->serverCtx = NULL;
                conn->serverSSL = NULL;
                conn->serverCert = NULL;
                conn->serverKey = NULL;
        }
}



/*****************************************************************************
*                             RESET FUNCTIONS
******************************************************************************/


/*
 * name:      removeClient
 * purpose:   removes a client from the clientList
 * arguments: the proxy instance, the table slot, the bucket index
 * returns:   none
 * effects:   removes the client's associated data, and closes the connection 
 *            with the client
 */
void removeClient(proxy *theProxy, int slot, int index)
{
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        DEBUG_PRINT("FUNCTION: removeClient: %d\n", client->clientSD);
        freeMITMFields(theProxy, slot, index);

        FD_CLR(client->clientSD, &theProxy->activeFDSet);
        close(client->clientSD);

        // resetClientMaxFD(theProxy, slot, index);

        // reset the clientSD / clientSSL / clientCtx field at the server struct
        int serverSD = theProxy->clientTable[slot].slotArray[index].serverSD;
        if (serverSD != -1) {
                int serverSlot = hashTableKey(theProxy, serverSD);
                int serverIndex = 0;
                if (getServerAtSlot(theProxy, serverSlot, &serverIndex, serverSD)) {
                        theProxy->clientTable[serverSlot].slotArray[serverIndex].clientSD = -1;
                        theProxy->clientTable[serverSlot].slotArray[serverIndex].clientSSL = NULL;
                        freeTableSlot(theProxy, slot, index);
                        if (theProxy->clientTable[serverSlot].slotArray[serverIndex].connActive) {
                                removeServer(theProxy, serverSlot, serverIndex);
                        }
                        return;
                }
        }

        freeTableSlot(theProxy, slot, index);
}


/*
 * name:      removeServer
 * purpose:   removes a server from the clientList
 * arguments: the proxy instance, the table slot, the bucket index
 * returns:   none
 * effects:   removes the server's associated data, and closes the connection 
 *            with the server
 */
void removeServer(proxy *theProxy, int slot, int index)
{
        connectionInfo *server = &theProxy->clientTable[slot].slotArray[index];
        DEBUG_PRINT("FUNCTION: removeServer: %d\n", server->serverSD);
        freeMITMFields(theProxy, slot, index);

        FD_CLR(server->serverSD, &theProxy->activeFDSet);
        close(server->serverSD);

        // resetServerMaxFD(theProxy, slot, index);

        // reset the serverSD / serverSSL / serverCtx field at the client struct
        int clientSD = theProxy->clientTable[slot].slotArray[index].clientSD;
        if (clientSD != -1) {
                int clientSlot = hashTableKey(theProxy, clientSD);
                int clientIndex = 0;
                if (getClientAtSlot(theProxy, clientSlot, &clientIndex, clientSD)) {
                        theProxy->clientTable[clientSlot].slotArray[clientIndex].serverSD = -1;
                        theProxy->clientTable[clientSlot].slotArray[clientIndex].serverSSL = NULL;
                        theProxy->clientTable[clientSlot].slotArray[clientIndex].serverCtx = NULL;
                        freeTableSlot(theProxy, slot, index);
                        removeClient(theProxy, clientSlot, clientIndex);
                        return;
                }
        }
        

        freeTableSlot(theProxy, slot, index);
}



/*
 * name:      freeTableSlot
 * purpose:   frees and resets all fields of a connectionInfo struct at a given 
 *            table slot
 * arguments: the proxy instance, the client bucket, the bucket index
 * returns:   none
 * effects:   none
 */
void freeTableSlot(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: freeTableSlot: \n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];
        client->clientSD = -1;
        client->serverSD = -1;
        client->isClient = false;
        client->mode = theProxy->proxyMode;

        client->bufferSize = -1;
        client->bufferRead = 0;
        if (client->readBuffer != NULL) {
                free(client->readBuffer);
                client->readBuffer = NULL;
        }
        
        client->headerSize = -1;
        client->headerRead = 0;
        if (client->msgHeader != NULL) {
                free(client->msgHeader);
                client->msgHeader = NULL;
        }

        client->contentSize = -1;
        client->contentRead = 0;
        if (client->msgContent != NULL) {
                free(client->msgContent);
                client->msgContent = NULL;
        }

        client->contentEncoding = -1;
        client->chunkedContent = false;
        client->divAdded = false;
        
        client->connActive = false;
        client->timeAdded = -1;

        if (client->serverURL != NULL) {
                free(client->serverURL);
                client->serverURL = NULL;
        }

        client->serverPort = -1;
        client->clientSSL = NULL;

        client->serverCtx = NULL;
        client->serverSSL = NULL;
        client->serverCert = NULL;
        client->serverKey = NULL;

        theProxy->clientTable[slot].numSlotItems--;
        theProxy->numClients--;
}


/*
 * name:      resetClientMaxFD
 * purpose:   resets the maxFD to the highest FD of the active sockets
 * arguments: the proxy instance, the table slot, the bucket index
 * returns:   none
 * effects:   none
 */
void resetClientMaxFD(proxy *theProxy, int slot, int index)
{
        connectionInfo *conn = &theProxy->clientTable[slot].slotArray[index];

        if (conn->clientSD != theProxy->maxFD) {
                return;
        }

        theProxy->maxFD = -1;
        for (int i = 0; i < theProxy->tableSize; i++) {
                for (int j = 0; j < theProxy->clientTable[i].numSlotItems; j++) {
                        connectionInfo *curr = &theProxy->clientTable[i].slotArray[j];
                        if (!curr->connActive) {
                                continue;
                        }
                        if (curr->isClient) {
                                if (curr->clientSD > theProxy->maxFD) {
                                        theProxy->maxFD = curr->clientSD;
                                }
                        } 
                        else {
                                if (curr->serverSD > theProxy->maxFD) {
                                        theProxy->maxFD = curr->serverSD;
                                }
                        }        
                }
        }
}


/*
 * name:      resetServerMaxFD
 * purpose:   resets the maxFD to the highest FD of the active sockets
 * arguments: the proxy instance, the table slot, the bucket index
 * returns:   none
 * effects:   none
 */
void resetServerMaxFD(proxy *theProxy, int slot, int index)
{
        connectionInfo *conn = &theProxy->clientTable[slot].slotArray[index];

        if (conn->serverSD != theProxy->maxFD) {
                return;
        }

        theProxy->maxFD = -1;
        for (int i = 0; i < theProxy->tableSize; i++) {
                for (int j = 0; j < theProxy->clientTable[i].numSlotItems; j++) {
                        connectionInfo *curr = &theProxy->clientTable[i].slotArray[j];

                        if (curr->isClient) {
                                if (curr->clientSD > theProxy->maxFD) {
                                        theProxy->maxFD = curr->clientSD;
                                }
                        } 
                        else {
                                if (curr->serverSD > theProxy->maxFD) {
                                        theProxy->maxFD = curr->serverSD;
                                }
                        }         
                }
        }
}