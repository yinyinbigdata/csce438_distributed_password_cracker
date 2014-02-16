#ifndef LSP_SERVER_C
#define LSP_SERVER_C

#include "api.h"

lsp_server* global_server;

// Setting LSP Parameters
double epoch_lth = 2;
double epoch_cnt = 5;

struct itimerval timer_server;

void lsp_server_resend_lastmsgbuf(lsp_server* a_srv, struct lsp_conn_desc* conn);

bool lsp_should_drop();

static void server_sig_timer(int i) {
    DEBUG("server_sig_timer:");
    struct lsp_conn_desc* conn;
    list_for_each_entry(conn, &global_server->ls_lcd_list, lcd_list) {
        if (conn->lcd_epoch_recv_flag) {
            conn->lcd_epoch_pass_num = 0;
            conn->lcd_epoch_recv_flag = 0;
        } else {
            conn->lcd_epoch_pass_num++;
        }
        DEBUG("server_sig_timer: connid %d epoch_pass_num %d", conn->lcd_connid, conn->lcd_epoch_pass_num);
        // time out
        if (conn->lcd_epoch_pass_num > epoch_cnt) {
            DEBUG("server_sig_timer: epoch pass num > epoch_cnt, resend, seqnum %d", conn->lcd_server_seqnum);
            lsp_server_resend_lastmsgbuf(global_server, conn);
            conn->lcd_epoch_pass_num = 0;
        }
    }
}

// Set length of epoch (in seconds)
void lsp_server_set_epoch_lth(double lth) {
    epoch_lth = lth;
    memset(&timer_server, 0, sizeof(struct itimerval));
    timer_server.it_interval.tv_sec = epoch_lth;
    timer_server.it_value.tv_sec = epoch_lth;
    //signal(SIGALRM, server_sig_timer);
    setitimer(ITIMER_REAL, &timer_server, NULL);
}

// Set number of epochs before timing out
void lsp_server_set_epoch_cnt(int cnt) {
    epoch_cnt = cnt;
}

bool lsp_server_store_lastmsgbuf(struct lsp_conn_desc* conn, uint8_t* buf, int len) {
    DEBUG("lsp_server_store_lastmsgbuf: len %d", len);
    memcpy(conn->lcd_last_buf, buf, len);
    conn->lcd_last_buf_len = len;
}

void lsp_server_resend_lastmsgbuf(lsp_server* a_srv, struct lsp_conn_desc* conn) {
    uint8_t* buf;
    int len;
    int addr_len = sizeof(struct sockaddr);
    int ret;
    
    buf = conn->lcd_last_buf;
    len = conn->lcd_last_buf_len;
    
    DEBUG("lsp_server_resend_lastmsgbuf: len %d", len);
    ret = sendto_maydrop(a_srv->ls_socket, buf, len, 0, (struct sockaddr*)&conn->lcd_client_addr, addr_len, false);
    if (ret < 0) {
        DEBUG("lsp_server_resend_lastmsgbuf: sendto failed");
    }
}

// Server API

lsp_server* lsp_server_create(int port) {
    lsp_server* server;
    struct sockaddr_in* server_addr;
    int addr_len = sizeof(struct sockaddr_in);
    
    server = (lsp_server*)malloc(sizeof(lsp_server));
    if (server == NULL) {
        PRINTF("lsp_server_create: malloc lsp_server ");
    }
    LOCK_INIT(&server->ls_lock);
    INIT_LIST_HEAD(&server->ls_lcd_list);
    server_addr = &server->ls_server_addr;

    
    server->ls_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (server->ls_socket < 0) {
        PRINTF("lsp_server_create: create socket failed\n");
        return NULL;
    }
    
    memset(server_addr, 0, addr_len);
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr->sin_port = htons(LSPPORT);
    
    // set SO_REUSEADDR so that we can re-use not fully deallocated chatrooms
	int optval = 1;
	setsockopt(server->ls_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
    
    if (bind(server->ls_socket, (struct sockaddr*)server_addr, addr_len) < 0) {
        PRINTF("lsp_server_create: bind failed");
        free(server); 
        server = NULL;
    }
    
    // set server sig timer
    // DEBUG("lsp_server_create: set sig timer");
    // memset(&timer_server, 0, sizeof(struct itimerval));
    // timer_server.it_interval.tv_sec = epoch_lth;
    // timer_server.it_value.tv_sec = epoch_lth;
    // signal(SIGALRM, server_sig_timer);
    // setitimer(ITIMER_REAL, &timer_server, NULL);
    
    global_server = server;
    
    return server;
}

struct lsp_conn_desc* find_conn_desc(lsp_server* a_srv, uint32_t conn_id) {
    struct lsp_conn_desc* conn;
    
    LOCK(&a_srv->ls_lock);
    list_for_each_entry(conn, &a_srv->ls_lcd_list, lcd_list) {
        if (conn->lcd_connid == conn_id) {
            UNLOCK(&a_srv->ls_lock);
            return conn;
        }
    }
    UNLOCK(&a_srv->ls_lock);
    return NULL;
}

// return new conn_id
uint32_t add_conn_desc(lsp_server* a_srv, struct sockaddr_in* client_addr) {
    struct lsp_conn_desc* conn;
    uint32_t connid = -1;
    conn = (struct lsp_conn_desc*)malloc(sizeof(struct lsp_conn_desc));
    INIT_LIST_HEAD(&conn->lcd_list);
    
    conn->lcd_client_addr = *client_addr;
    LOCK(&a_srv->ls_lock);
    a_srv->ls_lcd_maxid++;
    connid = a_srv->ls_lcd_maxid;
    conn->lcd_connid = connid;
    list_add_tail(&a_srv->ls_lcd_list, &conn->lcd_list);
    UNLOCK(&a_srv->ls_lock);
    return connid;
}

bool remove_conn_desc(lsp_server* a_srv, uint32_t connid) {
    struct lsp_conn_desc* conn;
    struct lsp_conn_desc* tmp;
    
    list_for_each_entry_safe(conn, tmp, &a_srv->ls_lcd_list, lcd_list) {
        if (conn->lcd_connid == connid) {
            list_del(&conn->lcd_list);
            free(conn);
            return true;
        }
    }
    
    return false;
}

// Read from connection. Return NULL when connection lost
// Returns number of bytes read. coon_id is an output parameter
int lsp_server_read(lsp_server* a_srv, void* pld, uint32_t* conn_id) {
    struct sockaddr_in client_addr;
    uint8_t buf[MAXDATASIZE];
    LSPMessage* msg;
    int len;
    int ret;
    int addr_len = sizeof(struct sockaddr_in);
    uint32_t new_conn_id;
    uint32_t seqnum;
    struct lsp_conn_desc* conn = NULL;

recv_again:    
    DEBUG("lsp_server_read: begin recvfrom");
    ret = recvfrom_maydrop(a_srv->ls_socket, buf, MAXDATASIZE, 0, (struct sockaddr *)&client_addr, &addr_len, true);
    DEBUG("lsp_server_read: read packet");
    if (ret == -1) {
        PRINTF("lsp_server_read: recvfrom get -1\n");
        return -1;
    }
    
    msg = lspmessage__unpack(NULL, ret, buf);
    len = msg->payload.len;
    *conn_id = msg->connid;
    seqnum = msg->seqnum;
    memcpy(pld, msg->payload.data, len);
    
    
    DEBUG("lsp_server_read: read msg:");
    dump_msg(msg);
    // add new conn
    if (msg->connid == 0 && seqnum == 0 && len == 0) {
        DEBUG("lsp_server_read: new conn");
        new_conn_id = add_conn_desc(a_srv, &client_addr);
        msg->connid = new_conn_id;
        lsp_msg_ack(msg, a_srv->ls_socket, &client_addr);
        goto out;
        //goto recv_again;
    }
    
    DEBUG("lsp_server_read: connid %d seqnum %d buf %s\n", msg->connid, msg->seqnum, pld);
    // old conn, find conn first
    conn = find_conn_desc(a_srv, msg->connid);
    if (conn == NULL) {
        DEBUG("lsp_server_read: can't find conn desc\n");
        goto out;
    }
    
    // check seqnum
    DEBUG("lsp_server_read: check seqnum, dump msg");
    dump_msg(msg);
    if (seqnum == conn->lcd_client_seqnum + 1) {
        DEBUG("lsp_server_read: recv client data, seqnum %d", seqnum);
        DEBUG("lsp_server_read: send ack");
        conn->lcd_client_seqnum = seqnum;
        lsp_msg_ack(msg, a_srv->ls_socket, &conn->lcd_client_addr);
    } else {
        DEBUG("lsp_server_read: wrong data, msg seqnum %d, lcd_client_seqnum %d", seqnum, conn->lcd_client_seqnum);
        goto recv_again;
    }
        
    // update epoch pass
    conn->lcd_epoch_recv_flag = 1;
    
    //lspmessage__free_unpacked(msg, NULL);

out:
    return len;
}

// Server Write. Should not send NULL
bool lsp_server_write(lsp_server* a_srv, void* pld, int lth, uint32_t conn_id) {
    struct lsp_conn_desc* conn;
    uint8_t* req_buf = NULL;
    int req_len, req_ret;
    LSPMessage req_msg = LSPMESSAGE__INIT;
    uint8_t ack_buf[MAXDATASIZE];
    int ack_len, ack_ret;
    LSPMessage* ack_msg;
    struct sockaddr_in client_addr;
    int addr_len = sizeof(struct sockaddr_in);
    
    conn = find_conn_desc(a_srv, conn_id);
    if (conn == NULL) {
        PRINTF("lsp_server_write: can't find conn \n");
        return false;
    }
    
    req_msg.connid = conn->lcd_connid;
    conn->lcd_server_seqnum++;
    req_msg.seqnum = conn->lcd_server_seqnum;
    req_msg.payload.data = malloc(sizeof(uint8_t) * lth);
    if (req_msg.payload.data == NULL) {
        PRINTF("lsp_server_write: malloc payload failed\n");
        return false;
    }
    req_msg.payload.len = lth;
    memcpy(req_msg.payload.data, pld, lth * sizeof(uint8_t));
    
    req_len = lspmessage__get_packed_size(&req_msg);
    req_buf = malloc(req_len);
    if (req_buf == NULL) {
        PRINTF("lsp_server_write: malloc buf failed\n");
        return false;
    }
    lspmessage__pack(&req_msg, req_buf);
    
    if (req_len == 0) {
        DEBUG("lsp_server_write: should not write null");
    }
    
    DEBUG("lsp_server_write: send msg connid %d seqnum %d buf: %s ;len %d\n", req_msg.connid, req_msg.seqnum, pld, req_len);
    lsp_server_store_lastmsgbuf(conn, req_buf, req_len);
    req_ret = sendto_maydrop(a_srv->ls_socket, req_buf, req_len, 0, (struct sockaddr*)&conn->lcd_client_addr, sizeof(struct sockaddr), true);
    if (req_ret != req_len) {
        DEBUG("lsp_server_write: send size mismatch req_len %d, req_ret %d", req_len, req_ret);
    }
    free(req_buf);
    
recv_ack:
    ack_ret = recvfrom_maydrop(a_srv->ls_socket, ack_buf, 4096, 0, (struct sockaddr *)&client_addr, &addr_len, false);
    if (ack_ret == -1) {
        DEBUG("lsp_server_create: receive init ack msg failed\n");
    }
    ack_msg = lspmessage__unpack(NULL, ack_ret, ack_buf);
    
    if (ack_msg->connid != conn->lcd_connid) {
        DEBUG("lsp_server_write: bug!!! connid mismatch");
    }

    if (ack_msg->seqnum == conn->lcd_server_seqnum && 
        ack_msg->connid == conn->lcd_connid &&
        ack_msg->payload.len == 0) {
        DEBUG("lsp_server_write: seqnum %d recv ack", conn->lcd_server_seqnum);
    } else {
        DEBUG("lsp_server_write: wrong ack, send seqnum %d, recv %d", conn->lcd_server_seqnum, ack_msg->seqnum);
        dump_msg(ack_msg);
        DEBUG("lsp_server_write: try again");
        memset(ack_buf, 0, MAXDATASIZE);
        goto recv_ack;
    }
    
    return true;
}

// Close connection.
bool lsp_server_close(lsp_server* a_srv, uint32_t conn_id) {
    remove_conn_desc(a_srv, conn_id);
}

#endif