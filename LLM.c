/*****************************************************************************
 *
 *      LLM.c
 *      
 *      Isabel Muste (imuste01)
 *      Marti Zentmaier (mzentm01)
 * 
 *      11/10/2024
 *      
 *      CS 112 Final Project
 * 
 *      This file contains the LLM functionality for the proxy, it makes the 
 *      LLM call and maintains the buffers and data retrieved and used for the 
 *      LLM call
 *      
 *
 *****************************************************************************/

#include "proxy.h"
#include "logging.h"
#include <curl/curl.h>


const char *url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev";
const char *x_api_key = "x-api-key: comp112iyk2IrCWK9T8Mq9WKjkvUs53JJz7heGdIvMrogA2"; 


/*
 * name:      initializeCategories
 * purpose:   initializes the categories buffer using the categories.txt file 
 *            so this buffer can be used for the LLM call
 * arguments: the proxy instance
 * returns:   none
 * effects:   stores the categories content in the buffer
 */
void initializeCategories(proxy *thisProxy) 
{
        FILE *file = fopen("categories.txt", "r");
        fseek(file, 0, SEEK_END);
        long fileSize = ftell(file);
        fseek(file, 0, SEEK_SET);
        char *categoriesContent = malloc(fileSize + 1);

        size_t bytesRead = fread(categoriesContent, 1, fileSize, file);
        categoriesContent[bytesRead] = '\0';
        fclose(file);
        
        // put proxy categories solution 
        thisProxy->connSolution = categoriesContent;
        INFO_PRINT("Connections Solution %s\n", categoriesContent);
}


/*
 * name:      makeLLMCall
 * purpose:   sets up the parameters to make the LLM call and extracts the 
 *            LLM response 
 * arguments: the proxy instance
 * returns:   none
 * effects:   none
 */
void makeLLMCall(proxy *theProxy)
{
        char response[4096] = "";

        makeProxyRequestLLM("4o-mini", "Please give one descriptive but obscure hint for each one of the following 4 categories. Don't directly mention the category and use this format for your respose: Category 1: [hint]; Category 2: [hint]; Category 3: [hint]; Category 4: [hint]. Please keep each hint around 300 characters.",
        theProxy->connSolution, response);

        INFO_PRINT("LLM response: %s", response);

        char *cat1, *cat2, *cat3, *cat4;
        extractResponse(theProxy, response, &cat1, &cat2, &cat3, &cat4);
}


/*
 * name:      extractResponse
 * purpose:   takes the entire LLM response and parses this into the 4 
 *            separate hints using the expected format returned by the LLM
 * arguments: the proxy instance, the response buffer
 * returns:   none
 * effects:   none
 */
void extractResponse(proxy *theProxy, char *response, char **cat1, char **cat2, 
        char **cat3, char **cat4)
{
        char *cat1Str = strstr(response, "Category 1:");
        int catStart = cat1Str - response + 12;
        char *cat2Str = strstr(response, "Category 2:");
        char *cat3Str = strstr(response, "Category 3:");
        char *cat4Str = strstr(response, "Category 4:");
        char *cat4End = strstr(response, "\", \"grade\"");

        int cat1Size = cat2Str - 4 - cat1Str - 12;
        int cat2Size = cat3Str - 4 - cat2Str - 12;
        int cat3Size = cat4Str - 4 - cat3Str - 12;
        int cat4Size = cat4End - cat4Str - 12;
        *cat1 = malloc(cat1Size + 1);
        *cat2 = malloc(cat2Size + 1);
        *cat3 = malloc(cat3Size + 1);
        *cat4 = malloc(cat4Size + 1);

        memcpy(*cat1, cat1Str + 12, cat1Size);
        memcpy(*cat2, cat2Str + 12, cat2Size);
        memcpy(*cat3, cat3Str + 12, cat3Size);
        memcpy(*cat4, cat4Str + 12, cat4Size);
        (*cat1)[cat1Size] = '\0';
        (*cat2)[cat2Size] = '\0';
        (*cat3)[cat3Size] = '\0';
        (*cat4)[cat4Size] = '\0';

        populateFinalDiv(theProxy, *cat1, *cat2, *cat3, *cat4);
}


/*
 * name:      populateFinalDiv
 * purpose:   takes the four populated hints and inserts them into the div 
 *            buffer used to display the hints on the page
 * arguments: the proxy instance, the slot and index in the table
 * returns:   none
 * effects:   stores the final div buffer in the LLMResponse field
 */
void populateFinalDiv(proxy *theProxy, char *cat1, char *cat2, char *cat3, char *cat4)
{
        int cat1Length = strlen(cat1);
        int cat2Length = strlen(cat2);
        int cat3Length = strlen(cat3);
        int cat4Length = strlen(cat4);
        int catLengths = cat1Length + cat2Length + cat3Length + cat4Length;

        char *htmlTemplate = 
        "<div id=\"hintBox\" class=\"M+I_Proxy\" style=\"display: none; position: fixed; top: 235px; right: 50px; width: 17%%; text-align: justify; z-index: 1000; border: 3px solid #b0a6f4; border-radius: 15px; padding: 10px; font-family: verdana; font-size: 15px;\">\n"
        "    <span id=\"hintContent\"></span>\n"
        "</div>\n"
        "\n"
        "<button id=\"hintButton\" style=\"position: fixed; top: 150px; right: 50px; padding: 10px 20px; background-color: #b0a6f4; border: 2px solid #b0a6f4; border-radius: 10px; font-family: verdana; font-size: 15px; cursor: pointer;\">\n"
        "    Show Hint\n"
        "</button>\n"
        "\n"
        "<div id=\"hintNav\" style=\"display: none; position: fixed; top: 200px; right: 50px;\">\n"
        "    <button id=\"prevHint\" style=\"padding: 3px 8px; border-radius: 5px; z-index: 1000; border: 2px solid #b0a6f4; background-color: white\">Previous</button>\n"
        "    <button id=\"nextHint\" style=\"padding: 3px 8px; border: 2px solid #b0a6f4; border-radius: 5px; z-index: 1000; background-color: white\">Next</button>\n"
        "</div>\n"
        "\n"
        "<button id=\"regenerateHintBtn\" style=\"display: none; position: fixed; top: 461px; right: 50px; padding: 10px 20px; background-color: #b0a6f4; border: 2px solid #b0a6f4; border-radius: 10px; font-family: verdana; font-size: 15px; cursor: pointer; margin-top: 10px;\">\n"
        "    REGENERATE HINTS\n"
        "</button>\n"
        "<script>"
        "const hints = [\n"
        "    \"Hint 1: %s\",\n"
        "    \"Hint 2: %s\",\n"
        "    \"Hint 3: %s\",\n"
        "    \"Hint 4: %s\"\n"
        "];\n"
        "let currentHintIndex = 0;\n"
        "\n"
        "function positionRegenerateButton() {\n"
        "    const hintBox = document.getElementById('hintBox');\n"
        "    const regenerateButton = document.getElementById('regenerateHintBtn');\n"
        "    const hintBoxHeight = hintBox.offsetHeight;\n"
        "    regenerateButton.style.top = (235 + hintBoxHeight + 5) + 'px';\n"
        "}\n"
        "\n"
        "// Call the function to position the button initially\n"
        "window.onload = positionRegenerateButton;\n"
        "\n"
        "document.getElementById('hintButton').addEventListener('click', function () {\n"
        "    const hintBox = document.getElementById('hintBox');\n"
        "    const hintNav = document.getElementById('hintNav');\n"
        "    const generateButton = document.getElementById('regenerateHintBtn');\n"
        "\n"
        "    // Toggle hint visibility\n"
        "    if (hintBox.style.display === 'none') {\n"
        "        hintBox.style.display = 'block';\n"
        "        hintNav.style.display = 'block';\n"
        "        generateButton.style.display = 'block';\n"
        "        this.innerText = 'Hide Hint';\n"
        "        updateHint();\n"
        "        positionRegenerateButton();\n"
        "    } else {\n"
        "        hintBox.style.display = 'none';\n"
        "        hintNav.style.display = 'none';\n"
        "        generateButton.style.display = 'none';\n"
        "        this.innerText = 'Show Hint';\n"
        "    }\n"
        "});\n"
        "\n"
        "document.getElementById('prevHint').addEventListener('click', function () {\n"
        "    if (currentHintIndex > 0) {\n"
        "        currentHintIndex--;\n"
        "    } else {\n"
        "        currentHintIndex = hints.length - 1;\n"
        "    }\n"
        "    updateHint();\n"
        "    positionRegenerateButton();\n"
        "});\n"
        "\n"
        "document.getElementById('nextHint').addEventListener('click', function () {\n"
        "    if (currentHintIndex < hints.length - 1) {\n"
        "        currentHintIndex++;\n"
        "    } else {\n"
        "        currentHintIndex = 0;\n"
        "    }\n"
        "    updateHint();\n"
        "    positionRegenerateButton();\n"
        "});\n"
        "\n"
        "document.getElementById('regenerateHintBtn').addEventListener('click', function () {\n"
        "    const regenerateButton = this;\n"
        "    regenerateButton.innerText = 'LOADING ...';\n"
        "    regenerateButton.disabled = true;\n"
        "\n"
        "    fetch('http://127.0.0.1:%d', {\n"
        "        method: 'POST',\n"
        "        headers: {\n"
        "            'Content-Type': 'application/json',\n"
        "            'X-Action': 'regenerate-hint'\n"
        "        }\n"
        "    })\n"
        "    .then(response => response.json())\n"
        "    .then(data => {\n"
        "        const newHints = data.hints;\n"
        "        if (Array.isArray(newHints) && newHints.length === 4) {\n"
        "            hints.forEach((hint, index) => {\n"
        "                const prefix = `Hint ${index + 1}: `;\n"
        "                hints[index] = prefix + newHints[index];\n"
        "            });\n"
        "\n"
        "            // Update the UI with the updated hints\n"
        "            const hintBox = document.getElementById('hintContent');\n"
        "            hintBox.innerHTML = hints.map(hint => `<p>${hint}</p>`).join('');\n"
        "\n"
        "            currentHintIndex = 0;\n"
        "            updateHint();\n"
        "            regenerateButton.innerText = 'REGENERATE HINTS';\n"
        "            regenerateButton.disabled = false;\n"
        "             positionRegenerateButton();\n"
        "        }\n"
        "    })\n"
        "    .catch(error => console.error('Error:', error));\n"
        "});\n"
        "\n"
        "function updateHint() {\n"
        "    const hintContent = document.getElementById('hintContent');\n"
        "    hintContent.innerText = hints[currentHintIndex];\n"
        "}\n"
        "</script>";

        int htmlLength = snprintf(NULL, 0, htmlTemplate, cat1, cat2, cat3, cat4, theProxy->portNumber);
        char *finalHtml = malloc(htmlLength + 1);
        snprintf(finalHtml, htmlLength + 1, htmlTemplate, cat1, cat2, cat3, cat4);
        theProxy->LLMResponse = finalHtml;
}



/*
 * name:      writeCallbackLLM
 * purpose:   sets up the callback for the LLM response
 * arguments: void pointer, size, nmemb, dat
 * returns:   the size of the callback
 * effects:   none
 */
size_t writeCallbackLLM(void *ptr, size_t size, size_t nmemb, char *data) 
{
        size_t totalSize = size * nmemb;
        strncat(data, ptr, totalSize);
        return totalSize;
}


/*
 * name:      makeProxyRequestLLM
 * purpose:   makes the proxy LLM request using the parameters specified
 * arguments: the model, the system, the query, and the response for the LLM
 * returns:   none
 * effects:   none
 */
void makeProxyRequestLLM(char *model, char *system, char *query, char *response)
{
        CURL *curl;
        CURLcode res;

        char *reqFormat = "{\n"
                "  \"model\": \"%s\",\n"
                "  \"system\": \"%s\",\n"
                "  \"query\": \"%s\",\n"
                "  \"temperature\": %.2f,\n"
                "  \"lastk\": %d,\n"
                "  \"session_id\": \"%s\"\n"
                "}";

        // JSON data to send in the POST request
        char request[4096];
        memset(request, 0, 4096);
        snprintf(request,
                sizeof(request),
                reqFormat,
                model,
                system,
                query,
                0.0,
                1,
                "GenericSession");

        INFO_PRINT("Initiating request: %s\n", request);

        // Initialize CURL
        curl = curl_easy_init();
        if (curl == NULL) {
                ERROR_PRINT("Failed to initialize CURL.\n");
                return;
        }

        // Set the URL of the Proxy Agent server server
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Set the Content-Type to application/json
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        // Add x-api-key to header
        headers = curl_slist_append(headers, x_api_key);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Add request 
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);

        // Set the write callback function to capture response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallbackLLM);

        // Set the buffer to write the response into
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        // Perform the POST request
        res = curl_easy_perform(curl);

        // Check if the request was successful
        if(res != CURLE_OK) {
                ERROR_PRINT("curl_easy_perform() failed: %s\n", 
                curl_easy_strerror(res));
        }

        // Cleanup
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
}


/*
 * name:      formatConnectionsSolution
 * purpose:   takes the full connection solution buffer and formats this to 
 *            store it to a file for later use
 * arguments: the proxy instance, the raw conection solution data
 * returns:   none
 * effects:   stores the formatted solution in a file
 */
void formatConnectionsSolution(proxy *theProxy, char *connSol)
{
        char *solutionFormat = ""
        "    Category 1: %s, with words: %s, %s, %s, %s; "
        "    Category 2: %s, with words: %s, %s, %s, %s; "
        "    Category 3: %s, with words: %s, %s, %s, %s; "
        "    Category 4: %s, with words: %s, %s, %s, %s; "
        "";

        char categories[4][128];
        char words[4][4][30];
        int counter = 0;
        int categoryNum = 0;
        int wordNum = 0;

        while (connSol[counter] != '\0') {
        if (connSol[counter] == 't' && strncmp(connSol + counter, "title", 5) == 0) {
                counter += 8;
                int i = 0;
                while (connSol[counter] != '\"') {
                        categories[categoryNum][i++] = connSol[counter++];
                }
                categories[categoryNum][i] = '\0';
                categoryNum++;
                wordNum = 0;
        }
        else if (connSol[counter] == 'c' && strncmp(connSol + counter, "content", 7) == 0) {
                counter += 10;
                int i = 0;
                while (connSol[counter] != '\"') {
                        words[categoryNum - 1][wordNum][i++] = connSol[counter++];
                }
                words[categoryNum - 1][wordNum][i] = '\0';
                wordNum++;
        } 
        else {
                counter++;
        }
        }

        char *solution = malloc(4192 * sizeof(char));
        snprintf(solution, 4192, solutionFormat,
                categories[0], words[0][0], words[0][1], words[0][2], words[0][3],
                categories[1], words[1][0], words[1][1], words[1][2], words[1][3],
                categories[2], words[2][0], words[2][1], words[2][2], words[2][3],
                categories[3], words[3][0], words[3][1], words[3][2], words[3][3]);

        theProxy->connSolution = solution;
        char *filename = "categories.txt";
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        ssize_t bytesWritten = write(fd, theProxy->connSolution, strlen(theProxy->connSolution));
        close(fd);
}



/*
 * name:      checkHintRegeneration
 * purpose:   checks if a hint regenerate header was sent from the javascript 
 *            connections code
 * arguments: the proxy, the slot of the table, the index of the bucket
 * returns:   true if the hint regenerate header was set, false otherwise
 * effects:   sends the CORS response header if the header field isn't set yet
 */
bool checkHintRegeneration(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: checkHintRegeneration\n");
        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        char *hintHeader = "regenerate-hint";
        char *endStr = strstr(client->msgHeader, hintHeader);
        
        // request is not complete, so we can't do anything yet
        if (endStr == NULL) {
                const char *corsOptionsHeader = 
                "HTTP/1.1 200 OK\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type, X-Action\r\n"
                "Content-Length: 0\r\n"
                "\r\n";
                write(client->clientSD, corsOptionsHeader, strlen(corsOptionsHeader));
                return false;
        }
        return true;
}


/*
 * name:      sendNewlyGeneratedHints
 * purpose:   generates new hints for the user and sends these to the browser 
 *            to be displayed to the user
 * arguments: the proxy, the slot of the table, the index of the bucket
 * returns:   none
 * effects:   generates new hints and writes to client
 */
void sendNewlyGeneratedHints(proxy *theProxy, int slot, int index)
{
        DEBUG_PRINT("FUNCTION: sendNewlyGeneratedHints\n");

        connectionInfo *client = &theProxy->clientTable[slot].slotArray[index];

        char LLMResponse[4096] = "";
        makeProxyRequestLLM("4o-mini", "Please give one descriptive but obscure hint for each one of the following 4 categories. Don't directly mention the category and use this format for your respose: Category 1: [hint]; Category 2: [hint]; Category 3: [hint]; Category 4: [hint]. Please keep each hint around 500 characters.",
        theProxy->connSolution, LLMResponse);
        char *cat1, *cat2, *cat3, *cat4;
        extractResponse(theProxy, LLMResponse, &cat1, &cat2, &cat3, &cat4);

        char response[4096];
        int responseLength = snprintf(response, sizeof(response),
                "{\"hints\": [\"%s\", \"%s\", \"%s\", \"%s\"]}",
                cat1, cat2, cat3, cat4);

        char fullResponse[8192];
        int fullResponseLength = snprintf(fullResponse, sizeof(fullResponse),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type, X-Action\r\n"
                "Content-Length: %d\r\n\r\n"
                "%s", responseLength, response);

        write(client->clientSD, fullResponse, fullResponseLength);
        removeClient(theProxy, slot, index);
}