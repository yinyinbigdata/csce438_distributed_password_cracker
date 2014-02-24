#ifndef REQUEST_C
#define REQUEST_C

#include <openssl/sha.h>
#include "api.h"
#include "lsp.pb-c.h"


void send_join_request(lsp_client* client, const char* dest, int port) {
    char* join_msg = "j";
    
    DEBUG("send_join_request: dest %s, port %d", dest, port);
    
    client = lsp_client_create(dest, port);
    if (client == NULL) {
        DEBUG("send_join_request: can't create client");
    }
    lsp_client_write(client, join_msg, strlen(join_msg));
}

void pass_increment(char* p, int len) {
    int i;
    
    for (i = len - 1; i >= 0; i++) {
        if (p[i] == 'z') {
            p[i] = 'a';
            continue;
        } else {
            p[i] += 1;
            break;
        }
    }
}

char* handle_crack_request(char* crack_req) {
    char* hash, * lower, * upper;
    char* delim = " ";
    char pass_hash[SHA_DIGEST_LENGTH];
    char converted[21];
    char* ret = NULL;
    int i;
    int len;
    
    strtok(crack_req, delim);
    hash = strtok(NULL, delim);
    lower = strtok(NULL, delim);
    upper = strtok(NULL, delim);
    len = strlen(lower);
    
    for(;;) {
        SHA1(lower, len, pass_hash);
        
        for (i = 0; i < 20; i++) {
            sprintf(converted + 2 * i, "%02x", pass_hash[i]);
        }
        
        if (strcmp(converted, hash) == 0) {
            ret = (char*)malloc(len + 2);
            sprintf(ret, "f ", 2);
            memcpy(ret + 2, lower, len);
            return ret;
        }
        
        if (strcmp(lower, upper) == 0)
            break;
        pass_increment(lower, len);
    }
    
    // "x": password not found
    ret = (char*)malloc(2);
    memset(ret, 0, 2);
    ret[0] = 'x';
    return ret;
}

void usage() {
    PRINTF("usage: ./worker dest:port");
}

int main(int argc, char* argv[]) {
    lsp_client* wk_client;
    char* server_ip;
    char* server_port_str;
    int server_port;

    int i;
    char* hash;
    char* lower;
    char* upper;
    char* delim = ":";
    char buffer[1024];
    char* ret;
    int bytes_read;
    char* join_msg = "j";
    
    // 0. argv check
    if (argc != 2) {
        usage();
        return -1;
    }
    
    // 1. join req
    server_ip = strtok(argv[1], delim);
    server_port_str = strtok(NULL, delim);
    server_port = atoi(server_port_str);
    
    // send_join_request(wk_client, server_ip, server_port);
    DEBUG("send_join_request: dest %s, port %d", server_ip, server_port);
    
    wk_client = lsp_client_create(server_ip, server_port);
    if (wk_client == NULL) {
        DEBUG("send_join_request: can't create client");
    }
    lsp_client_write(wk_client, join_msg, strlen(join_msg));
    
    
    // 2. do work loop
    for (;;) {
        bytes_read = lsp_client_read(wk_client, buffer);
        
        if (bytes_read == 0)
            continue;
        if (bytes_read < 0)
            break;
        
        if (buffer[0] != 'c') {
            DEBUG("worker: not crack req. recv %s", buffer);
            continue;
        }
        ret = handle_crack_request(buffer);
        lsp_client_write(wk_client, ret, strlen(ret));
        free(ret);
    }
    
    return 0;
}

#endif

