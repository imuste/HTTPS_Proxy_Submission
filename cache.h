/******************************************************************************
 *
 *      cache.h
 *
 *      Isabel Muste (imuste01)
 *      09/17/2024
 *      
 *      CS 112 HW01
 * 
 *      Cache is a module that allows clients to cache server responses and 
 *      retrieve these responses if they exist in the cache. A response stays 
 *      in the cache as specified by the server or for an hour if no max age is 
 *      specified in the server response.
 *      The cache uses a hash table to allow for fast retrieval of responses
 *
 *
 *****************************************************************************/

#ifndef CACHE_H

#include "include.h"
#include "MurmurHash3.h"



/*
 * name:      cacheElement struct
 * purpose:   stores information about a file in the cache such as the file 
 *            name, the output file name, the file extension, its age, and 
 *            timing information
 */
typedef struct {
        char *URL;
        char *fullServerResponse;
        int serverPort;
        int serverResponseSize;

        unsigned long long maxAge;
        unsigned long long storageTime;
        unsigned long long staleTime;
        unsigned long long retrievalTime;

} cacheElement;


/*
 * name:      cacheSlot struct
 * purpose:   stores an array of cacheElements for a specific hash table 
 *            bucket as well as the number of items in the array
 */
typedef struct {

        int numSlotItems;
        cacheElement *slotArray;

} cacheSlot;


/*
 * name:      cacheInfo struct
 * purpose:   stores information about a cache instance such as its size, the
 *            underlying hash table, if it's full, and the time it was created
 */
typedef struct {

        cacheSlot *hashTable;
        int tableSize;
        int numItems;
        int maxNumItems;
        unsigned long long initialTime;

} cacheInfo;




/*****************************************************************
*                    FUNCTION DECLARATIONS
*****************************************************************/
cacheInfo *newCache(int size);

// Hash Table Interaction
void putRequest(cacheInfo *thisCache, char *URL, char *serverResponse, 
        int serverResponseSize, int serverHeaderSize, int serverPort);
int storeRequest(cacheInfo *thisCache, char *URL, char *serverResponse, 
        int serverResponseSize, int serverHeaderSize, int serverPort, 
        int tableSlot, int slotIndex);
int evictRequest(cacheInfo *thisCache);
char *getResponse(cacheInfo *thisCache, char *URL, int serverPort, 
        int *responseSize, int *currAge);
int findSlotIndex(cacheInfo *thisCache, int tableSlot, char *URL, 
        int serverPort);


// Server Response Parsing
int readResponseLine(char *messageBuffer, char *lineBuffer, int totalRead);
unsigned long long getMaxAge(cacheInfo *thisCache, char *serverResponse, 
        int serverHeaderSize);
unsigned long long checkControlHeaderLine(cacheInfo *thisCache, 
        char *currentLine);


// Timing Functions
unsigned long long getInitialTime();
unsigned long long getCurrTime(cacheInfo *thisCache);


// Hashing / Expanding Functions
unsigned int hashCacheKey(cacheInfo *thisCache, const char *key);
// bool checkTableExpansion(cacheInfo *thisCache);
// void expandTable(cacheInfo *thisCache);


// Freeing Memory
void freeCacheFields(cacheInfo *thisCache, int tableSlot, int slotIndex);
void freeMemory(cacheInfo *thisCache);


#endif