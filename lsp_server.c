#ifndef LSP_SERVER_C
#define LSP_SERVER_C

#include "api.h"
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
    
    if (bind(server->ls_socket, (struct sockaddr*)server_addr, addr_len) < 0) {
        PRINTF("lsp_server_create: bind failed");
        free(server); 
        server = NULL;
    }
    
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
    connid = a_srv->ls_lcd_maxid++;
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

void lsp_server_conn_ack(lsp_server* a_srv, struct sockaddr_in* client_addr, uint32_t connid) {
    LSPMessage msg = LSPMESSAGE__INIT;
    int len;
    uint8_t* buf;
    
    msg.connid = connid;
    msg.seqnum = 0;
    msg.payload.len = 0;
    
    len = lspmessage__get_packed_size(&msg);
    buf = malloc(len);
    lspmessage__pack(&msg, buf);
    
    sendto(a_srv->ls_socket, buf, len, 0, (struct sockaddr*)client_addr, sizeof(struct sockaddr));
    free(buf);
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
    
    DEBUG("lsp_server_read: begin recvfrom");
    ret = recvfrom(a_srv->ls_socket, buf, MAXDATASIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
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
    lspmessage__free_unpacked(msg, NULL);
    
    DEBUG("lsp_server_read: connid %d seqnum %d len", msg->connid, seqnum, len);
    // add new conn
    if (msg->connid == 0 && seqnum == 0 && len == 0) {
        DEBUG("lsp_server_read: new conn");
        new_conn_id = add_conn_desc(a_srv, &client_addr);
        lsp_server_conn_ack(a_srv, &client_addr, new_conn_id);
        goto out;
    }
    
    DEBUG("lsp_server_read: connid %d seqnum %d buf %s\n", msg->connid, msg->seqnum, pld);
    // old conn, find conn first
    conn = find_conn_desc(a_srv, msg->connid);
    if (conn == NULL) {
        DEBUG("lsp_server_read: can't find conn desc\n");
        goto out;
    }
    
    // check seqnum    
    if (seqnum == conn->lcd_seqnum + 1 && conn->lcd_seqnum == conn->lcd_ack_seqnum) {
        // receive new packet
        conn->lcd_seqnum = seqnum;
        //conn->lcd_ack_seqnum = seqnum;
        DEBUG("lsp_server_read: receive new packet, msg seqnum %d\n", msg->seqnum);
    } else if (seqnum < conn->lcd_seqnum) {
        // receive old packet
        DEBUG("lsp_server_read: receive old packet, msg seqnum %d, conn seqnum %d, conn ack_seqnum %d\n", 
                msg->seqnum, conn->lcd_seqnum, conn->lcd_ack_seqnum);
    } else if (seqnum > conn->lcd_seqnum + 1) {
        // receive future packet
        DEBUG("lsp_server_read: receive future packet, msg seqnum %d, conn seqnum %d, conn ack_seqnum %d\n", 
                msg->seqnum, conn->lcd_seqnum, conn->lcd_ack_seqnum);
    } else {
        // other unkown
        DEBUG("lsp_server_read: ack other unkown, msg seqnum %d, conn seqnum %d, conn ack_seqnum %d\n", 
                msg->seqnum, conn->lcd_seqnum, conn->lcd_ack_seqnum);
    }

out:
    return len;
}

// Server Write. Should not send NULL
bool lsp_server_write(lsp_server* a_srv, void* pld, int lth, uint32_t conn_id) {
    struct lsp_conn_desc* conn;
    uint8_t* buf;
    LSPMessage msg = LSPMESSAGE__INIT;
    int len;
    
    conn = find_conn_desc(a_srv, conn_id);
    if (conn == NULL) {
        PRINTF("lsp_server_write: can't find conn \n");
        return false;
    }
    
    //conn->lcd_seqnum++;
    conn->lcd_ack_seqnum++;
    msg.connid = conn->lcd_connid;
    msg.seqnum = conn->lcd_seqnum;
    msg.payload.data = malloc(sizeof(uint8_t) * lth);
    if (msg.payload.data == NULL) {
        PRINTF("lsp_server_write: malloc payload failed\n");
        return false;
    }
    msg.payload.len = lth;
    memcpy(msg.payload.data, pld, lth * sizeof(uint8_t));
    
    len = lspmessage__get_packed_size(&msg);
    buf = malloc(len);
    if (buf == NULL) {
        PRINTF("lsp_server_write: malloc buf failed\n");
        return false;
    }
    lspmessage__pack(&msg, buf);
    
    DEBUG("lsp_server_write: send msg connid %d seqnum %d buf: %s\n", msg.connid, msg.seqnum, pld);
    sendto(a_srv->ls_socket, buf, len, 0, (struct sockaddr*)&conn->lcd_client_addr, sizeof(struct sockaddr));
    
    return true;
}

// Close connection.
bool lsp_server_close(lsp_server* a_srv, uint32_t conn_id) {
    remove_conn_desc(a_srv, conn_id);
}


// Setting LSP Parameters

// Set length of epoch (in seconds)
void lsp_set_epoch_lth(double lth);

// Set number of epochs before timing out
void lsp_set_epoch_cnt(int cnt);

// Set fraction of packets that get dropped along each connection
void lsp_set_drop_rate(double rate);

#endif