/*****************************************************************************
 *
 *      tunnel.c
 *      
 *      Isabel Muste (imuste01)
 *      Marti Zentmaier (mzentm01)
 * 
 *      11/10/2024
 *      
 *      CS 112 Final Project
 * 
 *      Contains the function definitions for tunneling encrypted messages  
 *      between clients and servers
 *      
 *
 *****************************************************************************/

#include "proxy.h"
#include "logging.h"

#define TUNNEL 0
#define MITM 1


/*****************************************************************************
*                               TUNNEL SETUP
******************************************************************************/

/*
 * name:      setupTunnelToServer
 * purpose:   sets up the tunnel to the server by connecting to the server and 
 *            populating the appropriate struct fieds
 * arguments: the proxy, the client slot and index of the table
 * returns:   none
 * effects:   none
 */
void setupTunnelToServer(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: setupTunnelToServer\n");

        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        //get host IP address from hostname
        struct hostent *hostInfo;
        hostInfo = gethostbyname(client->serverURL);
        if (checkNullErrSSL(theProxy, slot, index, hostInfo, 1)) return;

        int serverSD = socket(AF_INET, SOCK_STREAM, 0);
        client->serverSD = serverSD;

        //ensure to close the socket and port after termination
        int opt = 1;
        int returnVal = setsockopt(serverSD, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (checkNegOneErrSSL(theProxy, slot, index, returnVal, 3)) return;

        //Client setup to connect the socket to the server and its IP address
        //this is the setup specifying the server info
        struct sockaddr_in serverAddress;
        memset(&serverAddress, 0, sizeof(struct sockaddr_in));
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr = *(struct in_addr *)hostInfo->h_addr;
        serverAddress.sin_port = htons(client->serverPort);
        returnVal = connect(serverSD, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
        if (checkNegOneErrSSL(theProxy, slot, index, returnVal, 4)) return;

        // add serverSD to the active set for select
        FD_SET(serverSD, &theProxy->activeFDSet);
        if (serverSD > theProxy->maxFD) {
                theProxy->maxFD = serverSD;
        }

        populateServerStruct(theProxy, serverSD, client);
}


/*
 * name:      populateServerStruct
 * purpose:   populates the relevant fields in the server struct
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
void populateServerStruct(proxy *theProxy, int serverSD, connectionInfo *client)
{
        int serverSlot = hashTableKey(theProxy, serverSD);
        int serverIndex = theProxy->clientTable[serverSlot].numSlotItems;
        theProxy->numClients++;
        theProxy->clientTable[serverSlot].numSlotItems++;

        connectionInfo *server = 
                &theProxy->clientTable[serverSlot].slotArray[serverIndex];
        server->isClient = false;
        server->serverSD = serverSD;
        server->clientSD = client->clientSD;
        server->connActive = true;
        server->serverPort = client->serverPort;
        server->mode = TUNNEL;

        int URLLength = strlen(client->serverURL);
        server->serverURL = malloc(URLLength);
        memcpy(server->serverURL, client->serverURL, URLLength);
}



/*****************************************************************************
*                             MESSAGE FORWARDING
******************************************************************************/


/*
 * name:      relayClientToServer
 * purpose:   reads a message from the server and forwards this to the client
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
void relayClientToServer(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION relayClientToServer\n");

        int bufferSize = 4096;
        char *readBuffer = malloc(bufferSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, readBuffer, 1)) return;

        int clientSD = theProxy->clientTable[slot].slotArray[index].clientSD;
        int serverSD = theProxy->clientTable[slot].slotArray[index].serverSD;

        int readReturn = read(clientSD, readBuffer, bufferSize);
        if (checkNegErrSSL(theProxy, slot, index, readReturn, 2)) return;

        readBuffer[readReturn] = '\0';
        if (checkNegOneErrSSL(theProxy, slot, index, serverSD, 3)) return;

        int totalSent = 0;
        while (totalSent < readReturn) {
                int writeReturn = write(serverSD, readBuffer + totalSent, 
                        readReturn - totalSent);
                if (checkNegErrSSL(theProxy, slot, index, writeReturn, 4)) return;
                totalSent += writeReturn;
        }

        DEBUG_PRINT("Sent client message to server\n");
        free(readBuffer);
}


/*
 * name:      relayServerToClient
 * purpose:   reads a message from the client and forwards this to the server
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   none
 */
void relayServerToClient(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION relayServerToClient\n");

        int bufferSize = 4096;
        char *readBuffer = malloc(bufferSize + 1);
        if (checkNullErrSSL(theProxy, slot, index, readBuffer, 1)) return;

        int clientSD = theProxy->clientTable[slot].slotArray[index].clientSD;
        int serverSD = theProxy->clientTable[slot].slotArray[index].serverSD;

        int readReturn = read(serverSD, readBuffer, bufferSize);
        if (checkNegErrSSL(theProxy, slot, index, readReturn, 2)) return;
        readBuffer[readReturn] = '\0';

        if (checkNegOneErrSSL(theProxy, slot, index, clientSD, 3)) return;

        int totalSent = 0;
        while (totalSent < readReturn) {
                int writeReturn = write(clientSD, readBuffer + totalSent, 
                        readReturn - totalSent);
                if (checkNegErrSSL(theProxy, slot, index, writeReturn, 4)) return;
                totalSent += writeReturn;
        }

        free(readBuffer);
}
