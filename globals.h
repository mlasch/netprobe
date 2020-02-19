#ifndef GLOBALS_H_
#define GLOBALS_H_

#include <pthread.h>

/* globals */
extern pthread_mutex_t collect_mutex;
extern int verbose_flag, nop_flag;

extern struct flow* insert_ptr;
extern struct flow* collect_ptr;
extern pthread_mutex_t collect_mutex;

#endif /* GLOBALS_H_ */
