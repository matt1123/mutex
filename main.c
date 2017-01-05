/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Multi-threaded DNS-like Simulation.
 * 
 * Don Porter - porter@cs.unc.edu
 * 
 * COMP 530 - University of North Carolina, Chapel Hill
 * 
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include "trie.h"

int separate_delete_thread = 0;
int simulation_length = 30; // default to 30 seconds
volatile int finished = 0;

// Uncomment this line for debug printing
#define DEBUG 1
#ifdef DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) 
#endif


static void *
delete_thread(void *arg) {
    while (!finished)
        check_max_nodes();
    return NULL;
}


static void *
client(void *arg)
{
    struct random_data rd;
    char rand_state[256];
    int32_t salt = time(0);

    // See http://lists.debian.org/debian-glibc/2006/01/msg00037.html
    rd.state = (int32_t*)rand_state;

    // Initialize the prng.  For testing, it may be helpful to reduce noise by 
    // temporarily setting this to a fixed value.
    initstate_r(salt, rand_state, sizeof(rand_state), &rd);

    while (!finished) {
        /* Pick a random operation, string, and ip */
        int32_t code;
        int rv = random_r(&rd, &code);
        int length = (code >> 2) & (64-1);
        char buf[64];
        int j;
        int32_t ip4_addr;
    
        if (rv) {
            printf("Failed to get random number - %d\n", rv);
            return NULL;
        }

        DEBUG_PRINT("Length is %d\n", length);
        memset(buf, 0, 64);
        /* Generate a random string in lowercase */
        for (j = 0; j < length; j+= 6) {
            int i;
            int32_t chars;

            rv = random_r(&rd, &chars);
            if (rv) {
                printf("Failed to get random number - %d\n", rv);
                return NULL;
            }

            for (i = 0; i < 6 && (i+j) < length; i++) {
                char val = ( (chars >> (5 * i)) & 31);
                if (val > 25)
                    val = 25;
                buf[j+i] = 'a' + val;
            }
        }

        DEBUG_PRINT ("Random string is %s\n", buf);
    

        switch (code % 3) {
        case 0: // Search
            DEBUG_PRINT ("Search\n");
            search (buf, length, NULL);
            break;
        case 1: // insert
            DEBUG_PRINT ("insert\n");
            rv = random_r(&rd, &ip4_addr);
            if (rv) {
                printf("Failed to get random number - %d\n", rv);
                return NULL;
            }
            insert (buf, length, ip4_addr);
            break;
        case 2: // delete
            DEBUG_PRINT ("delete\n");
            delete (buf, length);
            break;
        default:
            assert(0);
        }

        /* If we don't have a separate delete thread, the client needs to
         * make sure that the count didn't exceed the max.
         */
        if (!separate_delete_thread)
            check_max_nodes();
    }

    return NULL;
}


#define die(msg) do {                           \
        print();                                \
        printf(msg);                            \
        exit(1);                                \
    } while (0)

#define INSERT_TEST(ky, len, ip) do {                   \
        rv = insert(ky, len, ip);                       \
        if (!rv) die ("Failed to insert key " ky "\n"); \
    } while (0)             

#define SEARCH_TEST(ky, len, ex) do {                           \
        rv = search(ky, len, &ip);                              \
        if (!rv) die ("Failed fine insert key " ky "\n");   \
        if (ip != ex) die ("Found bad IP for key " ky "\n");  \
    } while (0)             

#define DELETE_TEST(ky, len) do {                       \
        rv = delete(ky, len);                           \
        if (!rv) die ("Failed to delete key " ky "\n"); \
    } while (0)             

int self_tests() {
    int rv;
    int32_t ip = 0;

    rv = insert ("abc", 3, 4);
    if (!rv) die ("Failed to insert key abc\n");

    rv = delete("abc", 3);
    if (!rv) die ("Failed to delete key abc\n");
    print();

    rv = insert ("google", 6, 5);
    if (!rv) die ("Failed to insert key google\n");

    rv = insert ("goggle", 6, 4);
    if (!rv) die ("Failed to insert key goggle\n");

    rv = delete("goggle", 6);
    if (!rv) die ("Failed to delete key goggle\n");

    rv = delete("google", 6);
    if (!rv) die ("Failed to delete key google\n");
  
    rv = insert ("ab", 2, 2);
    if (!rv) die ("Failed to insert key ab\n");

    rv = insert("bb", 2, 2);
    if (!rv) die ("Failed to insert key bb\n");

    print();
    printf("So far so good\n\n");

    rv = search("ab", 2, &ip);
    printf("Rv is %d\n", rv);
    if (!rv) die ("Failed to find key ab\n");
    if (ip != 2) die ("Found bad IP for key ab\n");
  
    rv = search("aa", 2, NULL);
    if (rv) die ("Found bogus key aa\n");

    ip = 0;

    rv = search("bb", 2, &ip);
    if (!rv) die ("Failed to find key bb\n");
    if (ip != 2) die ("Found bad IP for key bb\n");

    ip = 0;

    rv = delete("cb", 2);
    if (rv) die ("deleted bogus key cb\n");

    rv = delete("bb", 2);
    if (!rv) die ("Failed to delete real key bb\n");

    rv = search("ab", 2, &ip);
    if (!rv) die ("Failed to find key ab\n");
    if (ip != 2) die ("Found bad IP for key ab\n");

    ip = 0;

    rv = delete("ab", 2);
    if (!rv) die ("Failed to delete real key ab\n");
    // Tests suggested by Ruibin
    rv = insert("bbb", 3, 5);
    if (!rv) die ("Failed to insert key bbb\n");
    rv = insert("cccc", 4, 6);
    if (!rv) die ("Failed to insert key cccc\n");

    rv = insert("xaaa", 4, 7);
    if (!rv) die ("Failed to insert key xaaa\n");
  
    rv = search("cccc", 4, &ip);
    if (!rv) die ("Failed to find key cccc\n");
    if (ip != 6) die ("Found bad IP for key cccc\n");

    rv = delete("cccc", 4);
    if (!rv) die ("Failed to delete real key cccc\n");

    rv = delete("bbb", 3);
    if (!rv) die ("Failed to delete real key bbb\n");

    rv = delete("xaaa", 4);
    if (!rv) die ("Failed to delete real key xaaa\n");

    printf("%s\n","made it here 00" );

    // Tests suggested by James
    INSERT_TEST("google", 6, 1);
    INSERT_TEST("com", 3, 2);
    INSERT_TEST("edu", 3, 3);
    INSERT_TEST("org", 3, 4);
    INSERT_TEST("but", 3, 5);
    INSERT_TEST("pincher", 7, 7);
    INSERT_TEST("pinter", 6, 8);
    INSERT_TEST("roller", 6, 9);
    INSERT_TEST("simple", 6, 10);
    INSERT_TEST("file", 4, 11);
    INSERT_TEST("principle", 9, 12);

    // MY TEST
    INSERT_TEST("apple");
    INSERT_TEST("debugger");

    SEARCH_TEST("google", 6, 1);
    SEARCH_TEST("com", 3, 2);
    SEARCH_TEST("edu", 3, 3);
    SEARCH_TEST("org", 3, 4);
    SEARCH_TEST("but", 3, 5);
    // SEARCH_TEST("butter", 6, 6);
    SEARCH_TEST("pincher", 7, 7);
    SEARCH_TEST("pinter", 6, 8);
    SEARCH_TEST("roller", 6, 9);
    SEARCH_TEST("simple", 6, 10);
    SEARCH_TEST("file", 4, 11);
    SEARCH_TEST("principle", 9, 12);

    SEARCH_TEST("apple");
    SEARCH_TEST("debugger");

    printf("%s\n", "made it here 0");
    print();
  
    DELETE_TEST("google", 6);
    DELETE_TEST("com", 3);
    DELETE_TEST("edu", 3);
    DELETE_TEST("org", 3);
    DELETE_TEST("but", 3);
    // DELETE_TEST("butter", 6);
    // DELETE_TEST("pincher", 7);
    DELETE_TEST("pinter", 6);
    DELETE_TEST("roller", 6);
    DELETE_TEST("simple", 6);
    DELETE_TEST("file", 4);
    DELETE_TEST("principle", 9);

    DELETE_TEST("apple");
    DELETE_TEST("debugger");

    // Tests suggested by Kammy
    INSERT_TEST("zhriz", 5, 1); 
    INSERT_TEST("eeonbws", 7, 2); 
    INSERT_TEST("mfpmirs", 7, 3); 
    INSERT_TEST("pzkvlyi", 7, 14);
    INSERT_TEST("xzrtjbz", 7, 6);

    printf("%s\n", "made it here 1");
    print();

    SEARCH_TEST("xzrtjbz", 7, 6); 
    SEARCH_TEST("pzkvlyi", 7, 14);
    SEARCH_TEST("mfpmirs", 7, 3);
    SEARCH_TEST("eeonbws", 7, 2);
    SEARCH_TEST("zhriz", 5, 1); 

  
    DELETE_TEST("mfpmirs", 7);
    DELETE_TEST("xzrtjbz", 7); 
    DELETE_TEST("eeonbws", 7);
    DELETE_TEST("zhriz", 5); 
    DELETE_TEST("pzkvlyi", 7);
  
    printf("End of self-tests, tree is:\n");
    print();
    printf("End of self-tests\n");
    return 0;
}

void help() {
    printf ("DNS Simulator.  Usage: ./dns-[variant] [options]\n\n");
    printf ("Options:\n");
    printf ("\t-c numclients - Use numclients threads.\n");
    printf ("\t-h - Print this help.\n");
    printf ("\t-l length - Run clients for length seconds.\n");
    printf ("\t-t  - Run a separate delete thread.\n");
    printf ("\n\n");
}

int main(int argc, char ** argv) {
    int numthreads = 1; // default to 1
    int c, i, rv;
    pthread_t *tinfo;

    // Read options from command line:
    //   # clients from command line, as well as seed file
    //   Simulation length
    //   Block if a name is already taken ("Squat")
    while ((c = getopt (argc, argv, "c:hl:t")) != -1) {
        switch (c) {
        case 'c':
            numthreads = atoi(optarg);
            break;
        case 'h':
            help();
            return 0;
        case 'l':
            simulation_length = atoi(optarg);
            break;
        case 't':
            separate_delete_thread = 1;
            break;
        default:
            printf ("Unknown option\n");
            help();
            return 1;
        }
    }

    // Create initial data structure, populate with initial entries
    // Note: Each variant of the tree has a different init function, statically compiled in
    init(numthreads);
    srandom(time(0));

    // Run the self-tests if we are in debug mode 
#ifdef DEBUG
    self_tests();
#endif

    // Launch client threads
    tinfo = calloc(numthreads + separate_delete_thread, sizeof(pthread_t));
    for (i = 0; i < numthreads; i++) {

        rv = pthread_create(&tinfo[i], NULL,
                            &client, NULL);
        if (rv != 0) {
            printf ("Thread creation failed %d\n", rv);
            return rv;
        }
    }

    if (separate_delete_thread) {
        rv = pthread_create(&tinfo[numthreads], NULL,
                            &delete_thread, NULL);
        if (rv != 0) {
            printf ("Delete thread creation failed %d\n", rv);
            return rv;
        }
    }

    // After the simulation is done, shut it down
    sleep (simulation_length);
    finished = 1;

    // Wait for all clients to exit.  If we are allowing blocking,
    // cancel the threads, since they may hang forever
    if (separate_delete_thread) {
        shutdown_delete_thread();
    }

    for (i = 0; i < numthreads; i++) {
        int rv = pthread_join(tinfo[i], NULL);
        if (rv != 0)
            printf ("Uh oh.  pthread_join failed %d\n", rv);
    }

#ifdef DEBUG  
    /* Print the final tree for fun */
    print();
#endif
  
    return 0;
}