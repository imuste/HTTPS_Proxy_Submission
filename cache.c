/******************************************************************************
 *
 *      cache.c
 *
 *      Isabel Muste (imuste01)
 *      11/11/2024
 *      
 *      CS 112 Final Project
 * 
 *      cache.c is the implementation of the cache module with no known bugs
 *
 *
 *****************************************************************************/

#include "cache.h"


/*
 * name:      newCache
 * purpose:   creates a new cache instance which is returned to the caller
 * arguments: the cache size
 * returns:   a reference to the cache struct
 * effects:   allocates memory for the cache struct and the underlying array
 */
cacheInfo *newCache(int size)
{
        cacheInfo *theInfo = malloc(sizeof(cacheInfo));
        assert(theInfo != NULL);

        theInfo->hashTable = (cacheSlot *)malloc(size * sizeof(cacheSlot));
        assert(theInfo->hashTable != NULL);

        for (int i = 0; i < size; i++) {
                theInfo->hashTable[i].slotArray = 
                        (cacheElement *)malloc(10 * sizeof(cacheElement));
                assert(theInfo->hashTable[i].slotArray != NULL);

                theInfo->hashTable[i].numSlotItems = 0;
        }

        theInfo->tableSize = size;
        theInfo->numItems = 0;
        theInfo->maxNumItems = (int)(size * 0.75);
        theInfo->initialTime = getInitialTime();
        
        return theInfo;
}


/******************************************************************************
*                           HASH TABLE INTERACTION
******************************************************************************/

/*
 * name:      putRequest
 * purpose:   puts a new request into the cache and evicts an old one if necessary
 * arguments: cache struct, the full request, server response, URL, server port
 * returns:   none
 * effects:   none
 */
void putRequest(cacheInfo *thisCache, char *URL, char *serverResponse, 
        int serverResponseSize, int serverHeaderSize, int serverPort)
{       
        // determine if the file exists already
        bool responseFound = false;
        int tableSlot = hashCacheKey(thisCache, URL);
        int slotIndex = findSlotIndex(thisCache, tableSlot, URL, serverPort);
        if (slotIndex != -1) {
                responseFound = true;
        }

        // a valid response was found
        if (responseFound) {
                freeCacheFields(thisCache, tableSlot, slotIndex);
                storeRequest(thisCache, URL, serverResponse, serverResponseSize, 
                        serverHeaderSize, serverPort, tableSlot, slotIndex);
                return;
        }

        // no valid response was found, so store the item
        if (!responseFound && thisCache->numItems >= thisCache->maxNumItems) {
                evictRequest(thisCache);
        }
        storeRequest(thisCache, URL, serverResponse, serverResponseSize, 
                serverHeaderSize, serverPort, tableSlot, 
                thisCache->hashTable[tableSlot].numSlotItems);
        thisCache->hashTable[tableSlot].numSlotItems++;
        thisCache->numItems++;
}



/*
 * name:      storeRequest
 * purpose:   stores the information about the request in the cache
 * arguments: cache instance, URL, server response, cache slot
 * returns:   int indicating success or failure
 * effects:   none
 */
int storeRequest(cacheInfo *thisCache, char *URL, char *serverResponse, 
        int serverResponseSize, int serverHeaderSize, int serverPort, 
        int tableSlot, int slotIndex)
{
        unsigned long long currTime = getCurrTime(thisCache);
        unsigned long long maxAge = getMaxAge(thisCache, serverResponse, 
                serverHeaderSize);

        cacheElement *elem = 
                &thisCache->hashTable[tableSlot].slotArray[slotIndex];

        elem->URL = URL;
        elem->fullServerResponse = serverResponse;
        elem->serverResponseSize = serverResponseSize;
        elem->serverPort = serverPort;
        elem->storageTime = currTime;
        elem->retrievalTime = currTime;
        elem->staleTime = currTime + maxAge;
        elem->maxAge = maxAge;

        return 0;
}


/*
 * name:      evictRequest
 * purpose:   evicts a stale item or the least recently retrieved item from the cache
 * arguments: cache instance
 * returns:   the cache slot of the evicted item
 * effects:   frees memory for evicted item
 */
int evictRequest(cacheInfo *thisCache)
{
        unsigned long long currentTime = getCurrTime(thisCache);
        bool staleFileFound = false;
        int staleSlot = 0, staleIndex = 0;
        unsigned long long oldestRetrievedTime = ULLONG_MAX;
        int oldestRetrievedSlot = 0, oldestRetrievedIndex = 0;

        for (int i = 0; i < thisCache->tableSize; i++) {
                for (int j = 0; j < thisCache->hashTable[i].numSlotItems; j++) {
                        cacheElement elem = 
                                thisCache->hashTable[i].slotArray[j];

                        //find any stale files
                        if (elem.staleTime < currentTime) {
                                staleFileFound = true;
                                staleSlot = i;
                                staleIndex = j;
                                break;
                        }

                        //if a file was retrieved, find lowest retrieval time
                        if (elem.retrievalTime < oldestRetrievedTime) {
                                oldestRetrievedTime = elem.retrievalTime;
                                oldestRetrievedSlot = i;
                                oldestRetrievedIndex = j;
                        }
                }
        }

        //return the first stale item found, or the least recently retrieved
        if (staleFileFound) {
                freeCacheFields(thisCache, staleSlot, staleIndex);
                return staleSlot;
        }
        else {
                freeCacheFields(thisCache, oldestRetrievedSlot, 
                        oldestRetrievedIndex);
                return oldestRetrievedSlot;
        }
}


/*
 * name:      getResponse
 * purpose:   retrieves an item from the cache if it is not stale
 * arguments: cache instance, URL, item age reference
 * returns:   the cached response or NULL if item is stale or not found
 * effects:   none
 */
char *getResponse(cacheInfo *thisCache, char *URL, int serverPort,
        int *responseSize, int *currAge)
{
        bool itemFound = false;
        unsigned long long currTime = getCurrTime(thisCache);

        unsigned int hashVal = hashCacheKey(thisCache, URL);

        for (int i = 0; i < thisCache->hashTable[hashVal].numSlotItems; i++) {

                cacheElement elem = thisCache->hashTable[hashVal].slotArray[i];
                if ((strcmp(elem.URL, URL) == 0) 
                && elem.serverPort == serverPort) {

                        if (currTime < elem.staleTime) {
                                itemFound = true;
                                elem.retrievalTime = currTime;
                                unsigned long long theAge = 
                                        currTime - elem.storageTime;

                                *currAge = (int)(theAge / 1000000000);
                                *responseSize = elem.serverResponseSize;
                                return elem.fullServerResponse;
                        }
                        return NULL;
                }
        }
        return NULL;
}


/*
 * name:      findSlotIndex
 * purpose:   finds the slot in the given hash table bucket that an item is in
 * arguments: cache instance, the table bucket, the URL (key)
 * returns:   the slot the item was found in or -1 if it doesn't exist
 * effects:   none
 */
int findSlotIndex(cacheInfo *thisCache, int tableSlot, char *URL, 
        int serverPort)
{
        int slotIndex = -1;
        int slotItems = thisCache->hashTable[tableSlot].numSlotItems;

        for (int i = 0; i < slotItems; i++) {
                cacheElement elem = 
                        thisCache->hashTable[tableSlot].slotArray[i];

                if (strcmp(elem.URL, URL) == 0) {
                        if (elem.serverPort == serverPort) {
                                slotIndex = i;
                                break;
                        }
                }
        }

        return slotIndex;
}


/******************************************************************************
*                          SERVER RESPONSE PARSING
******************************************************************************/

/*
 * name:      readResponseLine
 * purpose:   reads a line from the message and stores it in the lineBuffer
 * arguments: message buffer, line buffer, total bytes read
 * returns:   number of total bytes read
 * effects:   none
 */
int readResponseLine(char *messageBuffer, char *lineBuffer, int totalRead)
{
        int bytesRead = 0;

        // read one char at a time until we reach EOF or \n
        while ((messageBuffer[totalRead + bytesRead] != '\n') && 
                (messageBuffer[totalRead + bytesRead] != '\0')) {
                lineBuffer[bytesRead] = messageBuffer[totalRead + bytesRead];
                bytesRead++;
                
        }
        lineBuffer[bytesRead] = '\0';
        return totalRead + bytesRead + 1;
}



/*
 * name:      getMaxAge
 * purpose:   retrieves the max age of a cache item from the server response header
 * arguments: the cache instance, the reponse header
 * returns:   the maximum age of the cache item in nanoseconds
 * effects:   none
 */
unsigned long long getMaxAge(cacheInfo *thisCache, char *serverResponse, 
        int serverHeaderSize)
{
        char *currentLine;
        unsigned long long maxAge;
        maxAge = ((unsigned long long)3600 * (unsigned long long)1000000000);

        int totalRead = 0;
        while (totalRead < serverHeaderSize) {
                currentLine = malloc(200);
                assert(currentLine != NULL);
                totalRead = readResponseLine(serverResponse, currentLine, 
                        totalRead);

                //we have potentially found the cache control header line
                int age = checkControlHeaderLine(thisCache, currentLine);
                if (age != -1) {
                        break;
                }
                maxAge = age;
                free(currentLine);
        }

        return maxAge;
}


/*
 * name:      checkControlHeaderLine
 * purpose:   checks a header line to see if it is the cache control line 
 *            specifying the max age for the server response
 * arguments: cache instance, the current header line
 * returns:   -1 (large value b/c unsigned) if line wasn't found, otherwise 
 *            the max age value
 * effects:   none
 */
unsigned long long checkControlHeaderLine(cacheInfo *thisCache, 
        char *currentLine)
{
        char *maxAgeStr = NULL;
        unsigned long long maxAge = -1;

        if (currentLine[0] == 'C') {
                bool totalWord = true;
                char *word = "Cache-Control: max-age=";
                for (int i = 1; i < 23; i++) {
                        if (currentLine[i] != word[i]) {
                                totalWord = false;
                        }
                }
                if (totalWord) {
                        maxAgeStr = calloc(100, sizeof(char));
                        int i = 23;
                        while ((currentLine[i] != '\n') && (currentLine[i] != '\r')
                        && (currentLine[i] != ' ') && (currentLine[i] != '\0')) {
                                maxAgeStr[i - 23] = currentLine[i];
                                i++;
                        }
                        maxAge = ((unsigned long long)atoi(maxAgeStr)) * 1000000000;
                        free(maxAgeStr);
                        free(currentLine);
                        return maxAge;
                }
        }
        return maxAge;
}



/******************************************************************************
*                            TIMING FUNCTIONS
******************************************************************************/


/*
 * name:      getInitialTime
 * purpose:   gets the initial time at program startup
 * arguments: none
 * returns:   the initial time
 * effects:   none
 */
unsigned long long getInitialTime()
{
        struct timespec currTime;
        int returnVal = clock_gettime(CLOCK_MONOTONIC, &currTime);
        assert(returnVal != -1);
        unsigned long long theTime = (currTime.tv_sec * 1000000000ULL) + 
                currTime.tv_nsec;

        return theTime;
}



/*
 * name:      getCurrTime
 * purpose:   gets the current time minus the initial time to leave enough bits
 * arguments: none
 * returns:   the current time
 * effects:   none
 */
unsigned long long getCurrTime(cacheInfo *thisCache)
{
        struct timespec currTime;
        int returnVal = clock_gettime(CLOCK_MONOTONIC, &currTime);
        assert(returnVal != -1);
        unsigned long long theTime = (currTime.tv_sec * 1000000000ULL) + 
                currTime.tv_nsec - thisCache->initialTime;

        return theTime;
}



/******************************************************************************
*                            HASHING FUNCTION
******************************************************************************/

/*
 * name:      hash
 * purpose:   hashes the key of an item
 * arguments: cache instance, the key to hash
 * returns:   the hash of the item key
 * effects:   none
 */
unsigned int hashCacheKey(cacheInfo *thisCache, const char *key)
{
        unsigned int hash_output;
        MurmurHash3_x86_32(key, strlen(key), 42, &hash_output);
        return hash_output % thisCache->tableSize;
}



/******************************************************************************
*                        FREEING MEMORY FUNCTIONS
******************************************************************************/


/*
 * name:      freeCacheFields
 * purpose:   frees any cache fields that aren't freed yet
 * arguments: the cache instance, the cacheslot to free from
 * returns:   none
 * effects:   frees memory allocated
 */
void freeCacheFields(cacheInfo *thisCache, int tableSlot, int slotIndex)
{
        cacheElement *elem = 
                &thisCache->hashTable[tableSlot].slotArray[slotIndex];

        if (elem->URL != NULL) {
                free(elem->URL);
                elem->URL = NULL;
        }
        if (elem->fullServerResponse != NULL) {
                free(elem->fullServerResponse);
                elem->fullServerResponse = NULL;
        }
        elem->maxAge = -1;
        elem->retrievalTime = -1;
        elem->serverPort = -1;
        elem->serverResponseSize = -1;
        elem->staleTime = -1;
        elem->storageTime = -1;
}


/*
 * name:      freeMemory
 * purpose:   frees all memory allocated for the cached files
 * arguments: cache instance
 * returns:   none
 * effects:   none
 */
void freeMemory(cacheInfo *thisCache)
{
        if (thisCache == NULL) {
                return;
        }
        if (thisCache->hashTable == NULL) {
                free(thisCache);
                thisCache = NULL;
                return;
        }

        for (int i = 0; i < thisCache->tableSize; i++) {
                int slotItems = thisCache->hashTable[i].numSlotItems;
                for (int j = 0; j < slotItems; j++) {
                        cacheElement *elem = 
                                &thisCache->hashTable[i].slotArray[j];
                        if (elem->URL != NULL) {
                                free(elem->URL);
                                elem->URL = NULL;
                        }
                        if (elem->fullServerResponse != NULL) {
                                free(elem->fullServerResponse);
                                elem->fullServerResponse = NULL;
                        }
                }
        }
        free(thisCache->hashTable);
        thisCache->hashTable = NULL;
        free(thisCache);
        thisCache = NULL;
}
