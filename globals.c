
#include <pthread.h>
 

/* globals */
struct flow* insert_ptr = NULL;
struct flow* collect_ptr = NULL;
pthread_mutex_t collect_mutex = PTHREAD_MUTEX_INITIALIZER;
int verbose_flag = 0, nop_flag = 0;

