#ifndef LOGGING_H
#define LOGGING_H

#ifdef DEBUG
    #define DEBUG_PRINT(fmt, ...) \
        fprintf(stderr, "DEBUG - " fmt, ##__VA_ARGS__)
#else
    #define DEBUG_PRINT(fmt, ...) \
        do {} while (0)
#endif

#ifdef ERROR
    #define ERROR_PRINT(fmt, ...) \
        fprintf(stderr, "ERROR - " fmt, ##__VA_ARGS__)
#else
    #define ERROR_PRINT(fmt, ...) \
        do {} while (0)
#endif

#ifdef INFO
    #define INFO_PRINT(fmt, ...) \
        fprintf(stderr, "INFO - " fmt, ##__VA_ARGS__)
#else
    #define INFO_PRINT(fmt, ...) \
        do {} while (0)
#endif

#endif // LOGGING_H