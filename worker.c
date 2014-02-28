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

char* pass_increment(char* p, int len) {
    char temp[len];
    
    int i = len-1;
    strcpy(temp,p);
    // char *newstring = (char*)malloc(2);
    char *newstring = (char*)malloc(len);
    while(i>=0) {
        if(temp[i]=='z') {
                temp[i] = 'a';
                i = i-1;
        }
        else {
            temp[i]=temp[i]+1;
            strcpy(newstring, temp);
            return newstring;
        }
    }
}

int shaTest(char* input, int len, char* pass) {
	int i = 0;
    //note: must use unsigned char
	unsigned char temp[SHA_DIGEST_LENGTH];
	char buf[SHA_DIGEST_LENGTH*2];

	memset(buf, 0x0, SHA_DIGEST_LENGTH*2);
	memset(temp, 0x0, SHA_DIGEST_LENGTH);

	SHA1((unsigned char *)input, len, temp);

	for (i=0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf((char*)&(buf[i*2]), "%02x", temp[i]);
	}
	return strcmp(buf,pass)==0;
}

char* handle_crack_request(char* crack_req) {
    char* hash, * lower, * upper;
    char* delim = " ";
    char* ret = NULL;
    int i;
    int len;
    char* cur;
    char* cur_prev;
    
    DEBUG("handle_crack_request: %s", crack_req);
    strtok(crack_req, delim);
    hash = strtok(NULL, delim);
    lower = strtok(NULL, delim);
    upper = strtok(NULL, delim);
    len = strlen(lower);
    
    DEBUG("handle_crack_request: hash %s, lower %s, upper %s, len %d",
            hash, lower, upper, len);
    
    cur = (char*)malloc(len);
    if (cur == NULL) {
        DEBUG("handle_crack_request: malloc cur fail");
    }
    strcpy(cur, lower);
    for(;;) {
        DEBUG("handle_crack_request: sha1 on %s", cur);
        if (shaTest(cur, len, hash)) {
            ret = (char*)malloc(len + 2);
            sprintf(ret, "f ", 2);
            memcpy(ret + 2, cur, len);
            DEBUG("handle_crack_request: found password %s", cur);
            return ret;
        }
        
        DEBUG("handle_crack_request: compare %s %s", cur, upper);
        if (strcmp(cur, upper) == 0) {
            break;
        }

        cur_prev = cur;
        cur = pass_increment(cur_prev, len);
        free(cur_prev);
    }
    
    // "x": password not found
    ret = (char*)malloc(2);
    memset(ret, 0, 2);
    sprintf(ret, "x", 1);
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
        memset(buffer, 0, sizeof(buffer));
        bytes_read = lsp_client_read(wk_client, buffer);
        DEBUG("worker: recv %s", buffer);
        
        if (bytes_read == 0)
            continue;
        if (bytes_read < 0)
            break;
        
        if (buffer[0] != 'c') {
            DEBUG("worker: not crack req. recv %s", buffer);
            continue;
        }
        DEBUG("work: begin to crack");
        ret = handle_crack_request(buffer);
        lsp_client_write(wk_client, ret, strlen(ret));
        free(ret);
    }
    
    return 0;
}

#endif

