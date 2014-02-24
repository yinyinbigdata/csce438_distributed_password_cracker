#ifndef LSP_COMMON_C
#define LSP_COMMON_C

#include "api.h"

int drop_mode = 0;

double drop_rate = 0.01;

// Set fraction of packets that get dropped along each connection
void lsp_set_drop_rate(double rate) {
    drop_rate = rate;
}

bool lsp_should_drop() {
    struct timeval tv;
    uint32_t seed;
    double x;
    double x1;
    
    gettimeofday(&tv, NULL);
    seed = tv.tv_sec * 1000000 + tv.tv_usec;
    srand(seed);
    // x = (double)(rand() / RAND_MAX);
    x1 = rand();
    x = x1 / RAND_MAX;
    DEBUG("lsp_should_drop: x %f, drop_rate %f, x1 %f, RAND_MAX %d", x, drop_rate, x1, RAND_MAX);
    if (x < drop_rate) {
        DEBUG("lsp_should_drop: drop packet");
        return true;
    } else {
        DEBUG("lsp_should_drop: not drop");
        return false;
    }
}

void dump_msg(LSPMessage* msg) {
    DEBUG("dump_msg: msg connid %lu, seqnum %lu, msg len %lu", msg->connid, msg->seqnum, msg->payload.len);
}

ssize_t sendto_maydrop(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen, bool drop) {
    if (drop_mode && drop) {
        if (lsp_should_drop()) {
            DEBUG("sendto_maydrop: drop msg");
            return len;   
        }
    }
    
    DEBUG("sendto_maydrop: not drop msg");
    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);               
}

ssize_t recvfrom_maydrop(int sockfd, void *buf, size_t len, int flags,
                struct sockaddr *src_addr, socklen_t *addrlen, bool drop) {
    
    LSPMessage* msg;
    uint32_t connid;
    uint32_t seqnum;
    uint32_t msg_len;
    ssize_t ret;
    bool init_packet;

recv_again:
    DEBUG("recvfrom_maydrop: begin");
    ret = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (ret <= 0) {
        DEBUG("recvfrom_maydrop: recvfrom error, ret %d", ret);
        exit(-1);
        goto recv_again;
    }
    msg = lspmessage__unpack(NULL, ret, buf);
    msg_len = msg->payload.len;
    connid = msg->connid;
    seqnum = msg->seqnum;
    
    DEBUG("recvfrom_maydrop: recv data");
    dump_msg(msg);
    
    if (connid == 0 && seqnum == 0 && msg_len == 0) {
        // server read may drop init packet.
        DEBUG("recvfrom_maydrop: init packet, not drop");
        init_packet = true;
    }
    
    if (drop_mode && drop) {
        if (lsp_should_drop() && !init_packet) {
            DEBUG("recvfrom_maydrop: recv drop connid %d seqnum %d", connid, seqnum);
            memset(buf, 0, MAXDATASIZE);
            goto recv_again;
        }
    }
    
    return ret;             
}

void lsp_msg_ack(LSPMessage* data_msg, uint32_t socket, const struct sockaddr_in* addr) {
    LSPMessage ack_msg = LSPMESSAGE__INIT;
    int ack_len;
    uint8_t* ack_buf;
    
    ack_msg.connid = data_msg->connid;
    ack_msg.seqnum = data_msg->seqnum;
    ack_msg.payload.len = 0;
    
    ack_len = lspmessage__get_packed_size(&ack_msg);
    ack_buf = malloc(ack_len);
    lspmessage__pack(&ack_msg, ack_buf);
    
    DEBUG("lsp_msg_ack: data_msg info");
    dump_msg(data_msg);
    DEBUG("lsp_msg_ack: ack_msg info");
    dump_msg(&ack_msg);
    sendto_maydrop(socket, ack_buf, ack_len, 0, (struct sockaddr*)addr, sizeof(struct sockaddr), false);
    free(ack_buf);
    // already free ack_buf
    //lspmessage__free_unpacked(&ack_msg, NULL);
}

void lsp_ack(uint32_t connid, uint32_t seqnum, uint32_t socket, const struct sockaddr_in* addr) {
    LSPMessage ack_msg = LSPMESSAGE__INIT;
    int ack_len;
    uint8_t* ack_buf;
    
    ack_msg.connid = connid;
    ack_msg.seqnum = seqnum;
    ack_msg.payload.len = 0;
    
    ack_len = lspmessage__get_packed_size(&ack_msg);
    ack_buf = malloc(ack_len);
    lspmessage__pack(&ack_msg, ack_buf);
    
    sendto_maydrop(socket, ack_buf, ack_len, 0, (struct sockaddr*)addr, sizeof(struct sockaddr), false);
    free(ack_buf);
    // already free ack_buf
    //lspmessage__free_unpacked(&ack_msg, NULL);
}

bool lsp_is_ack_msg(LSPMessage* msg) {
    bool is_ack;
    if (msg->connid != 0 && msg->payload.len == 0)
        is_ack = true;
    else
        is_ack = false;
    
    return is_ack;
}

enum msg_type lsp_msg_type(LSPMessage* msg) {
    if (msg->connid == 0 && msg->seqnum == 0 && msg->payload.len == 0)
        return CONN_REQ;
    if (msg->connid != 0 && msg->seqnum == 0 && msg->payload.len == 0)
        return CONN_ACK;
    
    if (msg->connid != 0 && msg->seqnum > 0 && msg->payload.len > 0)
        return DATA_SEND;
    if (msg->connid != 0 && msg->seqnum > 0 && msg->payload.len == 0)
        return DATA_ACK;
}


#endif