#ifndef LSP_API_H
#define LSP_API_H

#include <stdio.h>
#include <stddef.h>
#include <sys/queue.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdbool.h>
#include <protobuf-c/protobuf-c.h>
#include <string.h>

#include "lsp.pb-c.h"
#include "list.h"

#define LSPPORT 8236
#define MAXDATASIZE 4096

#define LOCK_INIT(x)	pthread_mutex_init(x, 0)
#define LOCK(x)			pthread_mutex_lock(x)
#define TRY_LOCK(x)		pthread_mutex_trylock(x)
#define UNLOCK(x)		pthread_mutex_unlock(x)
#define LOCK_DESTROY(x)	pthread_mutex_destroy(x)

#define PRINTF(s, arg...)	printf(s "\n", ##arg)
#define DEBUG(s, arg...)	printf(s "\n", ##arg)


// Client API

typedef struct lsp_client_s {
    int32_t lc_socket;
    struct sockaddr_in lc_client_addr;
    struct sockaddr_in lc_server_addr;
    uint32_t lc_connid;
    uint32_t lc_seqnum;
    uint32_t lc_ack_seqnum;
    uint8_t lc_last_buf[MAXDATASIZE];
    int lc_last_buf_len;
} lsp_client;

typedef struct lsp_packet_s {
    uint32_t connid;
    uint32_t seqnum;
    uint8_t payload[];
} lsp_packet;

lsp_client* lsp_client_create(const char* dest, int port);

// Client Read. Return NULL when connection lost
// Returns number of bytes read
int lsp_client_read(lsp_client* a_client, uint8_t* pld);

// Client Write. Should not send NULL
bool lsp_client_write(lsp_client* a_client, uint8_t* pld, int lth);

// Close connection. Remember to free memory.
bool lsp_client_close(lsp_client* a_client);


// Server API

struct lsp_conn_desc {
    struct list_head lcd_list;
    uint32_t lcd_connid;
    uint32_t lcd_seqnum;
    uint32_t lcd_ack_seqnum;
    struct sockaddr_in lcd_client_addr;
};

typedef struct lsp_server_s {
    pthread_mutex_t ls_lock;
    int32_t ls_socket;
    struct sockaddr_in ls_server_addr;
    struct list_head ls_lcd_list;
    uint32_t ls_lcd_maxid;
} lsp_server;


lsp_server * lsp_server_create(int port);

// Read from connection. Return NULL when connection lost
// Returns number of bytes read. coon_id is an output parameter
int lsp_server_read(lsp_server* a_srv, void* pld, uint32_t* conn_id);

// Server Write. Should not send NULL
bool lsp_server_write(lsp_server* a_srv, void* pld, int lth, uint32_t conn_id);

// Close connection.
bool lsp_server_close(lsp_server* a_srv, uint32_t conn_id);


// Setting LSP Parameters

// Set length of epoch (in seconds)
void lsp_set_epoch_lth(double lth);

// Set number of epochs before timing out
void lsp_set_epoch_cnt(int cnt);

// Set fraction of packets that get dropped along each connection
void lsp_set_drop_rate(double rate);

#endif