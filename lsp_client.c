#ifndef LSP_CLIENT_C
#define LSP_CLIENT_C

#include "api.h"


lsp_client* lsp_client_create(const char* dest, int port) {
    lsp_client* client = NULL;
    struct sockaddr_in* server_addr;
    struct sockaddr_in* client_addr;
    int addr_len = sizeof(struct sockaddr);
    int addr_in_len = sizeof(struct sockaddr_in);
    uint8_t* req_buf;
    uint8_t ack_buf[MAXDATASIZE];
    int req_len, ack_len, ack_ret;
    LSPMessage req_msg = LSPMESSAGE__INIT;
    LSPMessage* ack_msg;
    uint32_t ack_connid;
    uint32_t ack_seqnum;
    int create_ret = 0;
    
    client = (lsp_client*)malloc(sizeof(lsp_client));
    if (client == NULL) {
        PRINTF("lsp_client_create: malloc client failed\n");
        return client;
    }
    
    client->lc_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (client->lc_socket < 0) {
        PRINTF("lsp_client_create: create socket failed\n");
        goto fail;
    }
    
    client_addr = &client->lc_client_addr;
    memset(client_addr, 0, addr_in_len);
    client_addr->sin_family = AF_INET;
    client_addr->sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr->sin_port = htons(0);
    
    if (bind(client->lc_socket, (struct sockaddr *)client_addr, addr_in_len) < 0) {
        PRINTF("lsp_client_create: bind failed\n");
        goto fail;
    }
    
    server_addr = &client->lc_server_addr;
    memset(server_addr, 0, sizeof(struct sockaddr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(LSPPORT);
    server_addr->sin_addr.s_addr = inet_addr(dest);
    
    // send init msg
    req_msg.connid = 0;
    req_msg.seqnum = 0;
    
    req_len = lspmessage__get_packed_size(&req_msg);
    req_buf = malloc(req_len);
    lspmessage__pack(&req_msg, req_buf);
    
    DEBUG("lsp_client_create: send conn req\n");
    sendto(client->lc_socket, req_buf, req_len, 0, (struct sockaddr *)server_addr, sizeof(struct sockaddr));
    free(req_buf);
    
    // receive init ack msg
    DEBUG("lsp_client_create: wait ack");
    
    ack_ret = recvfrom(client->lc_socket, ack_buf, 4096, 0, (struct sockaddr *)&(client->lc_server_addr), &addr_len);
    if (ack_ret == -1) {
        DEBUG("lsp_client_create: receive init ack msg failed\n");
        goto fail;
    }
    ack_msg = lspmessage__unpack(NULL, ack_ret, ack_buf);
    
    ack_connid = ack_msg->connid;
    ack_seqnum = ack_msg->seqnum;
    
    DEBUG("lsp_client_create: ack connid %d ack_seqnum %d", ack_connid, ack_seqnum);
    if (ack_connid != 0 && ack_seqnum == 0 && ack_msg->payload.len == 0) {
        DEBUG("lsp_client_create: conn establish, connid %d\n", ack_connid);
        client->lc_connid = ack_connid;
        create_ret = 1;
    }
    if (create_ret) 
        return client;
    
fail:
    free(client);
    client = NULL;
    return client;
}

bool lsp_client_store_lastmsgbuf(lsp_client* a_client, uint8_t* buf, int len) {
    uint32_t old_seqnum = a_client->lc_seqnum;
    
    memcpy(a_client->lc_last_buf, buf, len);
    a_client->lc_last_buf_len = len;
}

void lsp_client_resend_lastmsgbuf(lsp_client* a_client) {
    uint8_t* buf;
    int len;
    int addr_len = sizeof(struct sockaddr);
    
    buf = a_client->lc_last_buf;
    len = a_client->lc_last_buf_len;
    
    sendto(a_client->lc_socket, buf, len, 0, (struct sockaddr*)&a_client->lc_server_addr, addr_len);
}

// Client Read. Return NULL when connection lost
// Returns number of bytes read
int lsp_client_read(lsp_client * a_client, uint8_t * pld) {
    uint8_t buf[4096];
    int len;
    LSPMessage* msg;
    int ret;
    int addr_len = sizeof(struct sockaddr);
    
    ret = recvfrom(a_client->lc_socket, buf, 4096, 0, (struct sockaddr*)&(a_client->lc_server_addr), &addr_len);
    if (ret == -1) {
        DEBUG("lsp_client_read: recvfrom return -1\n");
        return -1;
    }
    
    msg = lspmessage__unpack(NULL, ret, buf);
    len = msg->payload.len;
    memcpy(pld, msg->payload.data, len);
    
    // check ack seqnum
    if (msg->seqnum == a_client->lc_seqnum && msg->seqnum == a_client->lc_ack_seqnum + 1) {
        a_client->lc_ack_seqnum = msg->seqnum;
        DEBUG("lsp_client_read: ack seqnum %d\n", msg->seqnum);
    } else {
        DEBUG("lsp_client_read: ack failed, except %d, received %d\n", a_client->lc_seqnum, msg->seqnum);
        DEBUG("lsp_client_read: resend last msg\n");
        lsp_client_resend_lastmsgbuf(a_client);
    }
    
    lspmessage__free_unpacked(msg, NULL);
    return len;
}


// Client Write. Should not send NULL
bool lsp_client_write(lsp_client* a_client, uint8_t* pld, int lth) {
    uint8_t* buf = NULL;
    int len;
    LSPMessage msg = LSPMESSAGE__INIT;
    
    if (a_client->lc_ack_seqnum < a_client->lc_seqnum) {
        DEBUG("lsp_client_write: wait ack, seqnum %d ack_seqnum %d\n", a_client->lc_seqnum, a_client->lc_ack_seqnum);
        lsp_client_resend_lastmsgbuf(a_client);
        return false;
    }
    
    msg.connid = a_client->lc_connid;
    a_client->lc_seqnum++;
    msg.seqnum = a_client->lc_seqnum;
    msg.payload.data = malloc(sizeof(uint8_t) * lth);
    if (msg.payload.data == NULL) {
        PRINTF("lsp_client_write: alloc payload failed\n");
        return -1;
    }
    msg.payload.len = lth;
    memcpy(msg.payload.data, pld, lth * sizeof(uint8_t));
    
    len = lspmessage__get_packed_size(&msg);
    buf = malloc(len);
    if (buf == NULL) {
        PRINTF("lsp_client_write: alloc buf failed\n");
        return -1;
    }
    lspmessage__pack(&msg, buf);
    
    DEBUG("lsp_client_write: send msg connid %d, seqnum %d, buf %s", msg.connid, msg.seqnum, pld);
    sendto(a_client->lc_socket, buf, len, 0, (struct sockaddr *)&a_client->lc_server_addr, sizeof(struct sockaddr));
    lsp_client_store_lastmsgbuf(a_client, buf, len);
    free(buf);
    free(msg.payload.data);
    
    return 0;
}

// Close connection. Remember to free memory.
bool lsp_client_close(lsp_client* a_client) {
    close(a_client->lc_socket);
    free(a_client);
    a_client = NULL;
    return true;
}


#endif