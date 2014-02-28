#ifndef REQUEST_C
#define REQUEST_C

#include "api.h"
#include "lsp.pb-c.h"

void usage() {
    PRINTF("usage: ./request host:port hash len");
}

int main(int argc, char* argv[]) {
    lsp_client* req_client;
    char req_msg[1024];
    int req_msg_len;
    char* server_ip;
    char* server_port_str;
    int server_port;
    char* hash;
    char* lower;
    char* upper;
    int i;
    char* delim = ":";
    int len;
    char ret_msg[1024];
    int ret_bytes;
    
    if (argc != 4) {
        usage();
        return;
    }
    
    server_ip = strtok(argv[1], delim);
    server_port_str = strtok(NULL, delim);
    server_port = atoi(server_port_str);
    hash = argv[2];
    len = atoi(argv[3]);
    
    DEBUG("server ip %s port %d", server_ip, server_port);  
     
    lower = malloc(len + 1);
    upper = malloc(len + 1);
    for (i = 0; i < len; i++) {
        lower[i] = 'a';
        upper[i] = 'z';
    }
    lower[len] = '\0';
    upper[len] = '\0';
    
    DEBUG("hash %s lower %s upper %s", hash, lower, upper);
    
    int offset = 0;
    char* space = " " ;
    memset(req_msg, 0, sizeof(req_msg));
    sprintf(req_msg, "c ", 2);
    offset += 2;
    // add hash
    sprintf(req_msg + offset, hash, strlen(hash));
    offset += strlen(hash);
    sprintf(req_msg + offset, space, 1);
    offset += 1;
    // lower
    sprintf(req_msg + offset, lower, len);
    offset += len;
    sprintf(req_msg + offset, space, 1);
    offset += 1;
    // upper
    sprintf(req_msg + offset, upper, len);
    offset += len;
    req_msg[offset] = '\0';
    
    DEBUG("request: req_msg %s", req_msg);
    
    req_client = lsp_client_create(server_ip, server_port);
    
    lsp_client_write(req_client, req_msg, strlen(req_msg) + 1);
    
    memset(ret_msg, 0, sizeof(ret_msg));
    ret_bytes = lsp_client_read(req_client, ret_msg);
    
    puts(ret_msg);
    
    return 0;
}



#endif

