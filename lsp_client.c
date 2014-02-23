#ifndef LSP_CLIENT_C
#define LSP_CLIENT_C

#include "api.h"

lsp_client * global_client;

// Setting client LSP Parameters
double epoch_lth = 2;
double epoch_cnt = 5;

struct itimerval timer_client;

void lsp_client_resend_lastmsgbuf(lsp_client* a_client);
void lsp_client_ack_lastmsgbuf(lsp_client* a_client);
bool lsp_client_store_lastmsgbuf(lsp_client* a_client, uint8_t* buf, int len);

static void client_sig_timer(int i) {
    DEBUG("client_sig_timer");
    if (global_client->lc_epoch_recv_flag) {
        global_client->lc_epoch_pass_num = 0;
        global_client->lc_epoch_recv_flag = 0;
    } else {
        global_client->lc_epoch_pass_num++;
    }
    
    // timeout
    if (global_client->lc_epoch_pass_num > epoch_cnt) {
        DEBUG("client_sig_timer: epoch pass num > epoch_cnt, terminate the conn");
        lsp_client_close(global_client);
        return;
    }
    
    if (global_client == NULL) 
        return;
    
    
    // resend conn req or last data msg
    lsp_client_resend_lastmsgbuf(global_client);
    
    //Send an acknowledgment message for the most recently received data message, or an acknowledgment with sequence number 0 if no data messages have been received.
    lsp_ack(global_client->lc_connid, global_client->lc_server_seqnum, 
            global_client->lc_socket, &global_client->lc_server_addr);
    
}

// Set length of epoch (in seconds)
void lsp_client_set_epoch_lth(double lth) {
    epoch_lth = lth;
    memset(&timer_client, 0, sizeof(struct itimerval));
    timer_client.it_interval.tv_sec = epoch_lth;
    timer_client.it_value.tv_sec = epoch_lth;
    signal(SIGALRM, client_sig_timer);
    signal(SIGALRM, client_sig_timer);
    setitimer(ITIMER_REAL, &timer_client, NULL);
}

// Set number of epochs before timing out
void lsp_client_set_epoch_cnt(int cnt) {
    epoch_cnt = cnt;
}

// client API
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
    
    // sig timer
    global_client = client;
    lsp_client_set_epoch_lth(epoch_lth);
    
    // set is_last_msg_ack
    client->lc_is_last_msg_ack = 1;
    
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
    
    // set SO_REUSEADDR so that we can re-use not fully deallocated chatrooms
	int optval = 1;
	setsockopt(client->lc_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
    
    
    if (bind(client->lc_socket, (struct sockaddr *)client_addr, addr_in_len) < 0) {
        PRINTF("lsp_client_create: bind failed\n");
        goto fail;
    }
    
    server_addr = &client->lc_server_addr;
    memset(server_addr, 0, sizeof(struct sockaddr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(port);
    server_addr->sin_addr.s_addr = inet_addr(dest);
    
    // send init msg
    req_msg.connid = 0;
    req_msg.seqnum = 0;
    req_msg.payload.len = 0;
    
    req_len = lspmessage__get_packed_size(&req_msg);
    req_buf = malloc(req_len);
    lspmessage__pack(&req_msg, req_buf);
    
    DEBUG("lsp_client_create: send conn req\n");
    lsp_client_store_lastmsgbuf(client, req_buf, req_len);
    sendto_maydrop(client->lc_socket, req_buf, req_len, 0, (struct sockaddr *)server_addr, sizeof(struct sockaddr), false);
    free(req_buf);
    
    // receive init ack msg
    DEBUG("lsp_client_create: wait ack");
    
    ack_ret = recvfrom_maydrop(client->lc_socket, ack_buf, 4096, 0, (struct sockaddr *)&(client->lc_server_addr), &addr_len, false);
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
        lsp_client_ack_lastmsgbuf(client);
        create_ret = 1;
    }
    
    if (!create_ret) {
        DEBUG("lsp_client_create: create_ret fail");
        goto fail;
    }
    return client;
    
fail:
// todo: puzzle on fail create
    // free(client);
    // client = NULL;
    return client;
}

bool lsp_client_store_lastmsgbuf(lsp_client* a_client, uint8_t* buf, int len) {
    uint32_t old_seqnum = a_client->lc_client_seqnum;
    
    if (a_client->lc_is_last_msg_ack == 0) {
        DEBUG("lsp_client_store_lastmsgbuf: last msg not ack. abort");
        DEBUG("lsp_client_store_lastmsgbuf: client seqnum %d", a_client->lc_client_seqnum);
        exit(-1);
    }

    memcpy(a_client->lc_last_buf, buf, len);
    a_client->lc_is_last_msg_ack = 0;
    a_client->lc_last_buf_len = len;
}

void lsp_client_resend_lastmsgbuf(lsp_client* a_client) {
    uint8_t* buf;
    int len;
    int addr_len = sizeof(struct sockaddr);
    
    buf = a_client->lc_last_buf;
    len = a_client->lc_last_buf_len;
    
    if (a_client->lc_is_last_msg_ack == 1)
        return;
    
    DEBUG("lsp_client_resend_lastmsgbuf: connid %d client_seqnum %d, len %d", 
            a_client->lc_connid, a_client->lc_client_seqnum, len);
    sendto_maydrop(a_client->lc_socket, buf, len, 0, (struct sockaddr*)&a_client->lc_server_addr, addr_len, false);
}

void lsp_client_ack_lastmsgbuf(lsp_client* a_client) {
    if (a_client->lc_is_last_msg_ack == 0) {
        a_client->lc_is_last_msg_ack = 1;
    }
}

// Client Read. Return NULL when connection lost
// Returns number of bytes read
int lsp_client_read(lsp_client * a_client, uint8_t * pld) {
    uint8_t buf[4096];
    int len;
    LSPMessage* msg;
    int ret;
    int addr_len = sizeof(struct sockaddr);
    enum msg_type msg_type;
    
    DEBUG("\n");
    DEBUG("lsp_client_read:###################");

recv_again:    
    ret = recvfrom_maydrop(a_client->lc_socket, buf, 4096, 0, (struct sockaddr*)&(a_client->lc_server_addr), &addr_len, true);
    if (ret == -1) {
        DEBUG("lsp_client_read: recvfrom return -1\n");
        return -1;
    }
    
    msg = lspmessage__unpack(NULL, ret, buf);
    len = msg->payload.len;  
    msg_type = lsp_msg_type(msg);
    
    if (msg_type != DATA_SEND) {
        DEBUG("lsp_client_read: recv not DATA_SEND msg, try again");
        dump_msg(msg);
        goto recv_again;
    }
   
    if (msg->seqnum == a_client->lc_server_seqnum + 1 && 
        msg->connid == a_client->lc_connid &&
        msg->payload.len != 0) {
        DEBUG("lsp_client_read: read server data, server_seqnum %d", msg->seqnum);
        a_client->lc_server_seqnum = msg->seqnum;
        a_client->lc_epoch_recv_flag = 1;
        memcpy(pld, msg->payload.data, len);
        lsp_msg_ack(msg, a_client->lc_socket, &a_client->lc_server_addr);
    } else {
        DEBUG("lsp_client_read: seqnum mismatch, sever_seqnum %d .dump msg\n", a_client->lc_server_seqnum);
        dump_msg(msg);
    }
        
    lspmessage__free_unpacked(msg, NULL);  
    
    DEBUG("lsp_client_read:###################\n\n");
    
    return len;
}


// Client Write. Should not send NULL
bool lsp_client_write(lsp_client* a_client, uint8_t* pld, int lth) {
    uint8_t* req_buf = NULL;
    int req_len, req_ret;
    LSPMessage req_msg = LSPMESSAGE__INIT;
    uint8_t ack_buf[MAXDATASIZE];
    int ack_len, ack_ret;
    LSPMessage* ack_msg;
    int addr_len = sizeof(struct sockaddr);
    enum msg_type msg_type;
    int retry;
    
    DEBUG("\n");
    DEBUG("lsp_client_write:###################");
    // send data
    req_msg.connid = a_client->lc_connid;
    a_client->lc_client_seqnum++;
    req_msg.seqnum = a_client->lc_client_seqnum;
    req_msg.payload.data = malloc(sizeof(uint8_t) * lth);
    if (req_msg.payload.data == NULL) {
        PRINTF("lsp_client_write: alloc payload failed\n");
        return -1;
    }
    req_msg.payload.len = lth;
    memcpy(req_msg.payload.data, pld, lth * sizeof(uint8_t));
    
    req_len = lspmessage__get_packed_size(&req_msg);
    req_buf = malloc(req_len);
    if (req_buf == NULL) {
        PRINTF("lsp_client_write: alloc buf failed\n");
        return -1;
    }
    lspmessage__pack(&req_msg, req_buf);
    
    DEBUG("lsp_client_write: send msg connid %d, seqnum %d, buf %s", req_msg.connid, req_msg.seqnum, pld);
    lsp_client_store_lastmsgbuf(a_client, req_buf, req_len);
    req_ret = sendto_maydrop(a_client->lc_socket, req_buf, req_len, 0, (struct sockaddr *)&a_client->lc_server_addr, sizeof(struct sockaddr), true);
    if (req_ret != req_len) {
        DEBUG("lsp_client_write: sendto ret %d", req_ret);
    }
    free(req_buf);
    free(req_msg.payload.data);
    
    // receive ack
    
recv_ack:
    retry++;
    if (retry > 5)
        goto out;
    DEBUG("lsp_client_write: wait on ack");
    ack_ret = recvfrom_maydrop(a_client->lc_socket, ack_buf, 4096, 0, (struct sockaddr *)&(a_client->lc_server_addr), &addr_len, false);
    if (ack_ret == -1) {
        DEBUG("lsp_client_create: receive init ack msg failed\n");
    }
    ack_msg = lspmessage__unpack(NULL, ack_ret, ack_buf);
    msg_type = lsp_msg_type(ack_msg);
    
    if (msg_type != DATA_ACK) {
        DEBUG("lsp_client_write: recv not DATA_ACK, try again");
        dump_msg(ack_msg);
        goto recv_ack;
    }
    
    if (ack_msg->seqnum == a_client->lc_client_seqnum && 
        ack_msg->connid == a_client->lc_connid &&
        ack_msg->payload.len == 0) {
        DEBUG("lsp_client_write: seqnum %d recv ack", a_client->lc_client_seqnum);
        lsp_client_ack_lastmsgbuf(a_client);
    } else {
        DEBUG("lsp_client_write: wrong ack, send seqnum %d, recv %d", a_client->lc_client_seqnum, ack_msg->seqnum);
        dump_msg(ack_msg);
        DEBUG("lsp_ciient_write: try again");
        memset(ack_buf, 0, MAXDATASIZE);
        goto recv_ack;
    }
    
out:    
    DEBUG("lsp_client_write:###################\n\n");
    return true;
}

// Close connection. Remember to free memory.
bool lsp_client_close(lsp_client* a_client) {
    close(a_client->lc_socket);
    free(a_client);
    a_client = NULL;
    return true;
}


#endif