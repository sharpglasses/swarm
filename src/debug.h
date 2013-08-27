#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdio.h>

#define debug(X, ...)                                                    \
  do {                                                                  \
    struct tm td;                                                       \
    struct timeval tv;                                                  \
    struct timezone tz;                                                 \
    FILE * out = stdout;                                                \
    if (X) {                                                            \
      gettimeofday (&tv, &tz);                                          \
      localtime_r (&tv.tv_sec, &td);                                    \
      fprintf (out, "(DEBUG %02d:%02d:%02d.%03d %s:%d %s) ", td.tm_hour, td.tm_min, td.tm_sec, (int) (tv.tv_usec / 1000), __FILE__, __LINE__, __FUNCTION__); \
      fprintf (out, __VA_ARGS__);                                       \
      fprintf (out, "\n");                                              \
      fflush (out);                                                     \
    }                                                                   \
  } while (0);
