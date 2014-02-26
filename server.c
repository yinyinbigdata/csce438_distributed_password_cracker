#ifndef SERVER_C
#define SERVER_C

#include <pthread.h>
#include "api.h"
#include "lsp.pb-c.h"

#define LOCK_INIT(x)          pthread_mutex_init(x, 0)
#define LOCK(x)               pthread_mutex_lock(x)
#define TRY_LOCK(x)           pthread_mutex_trylock(x)
#define UNLOCK(x)             pthread_mutex_unlock(x)
#define LOCK_DESTROY(x)       pthread_mutex_destroy(x)

enum dpc_msg_type {
    JOIN_REQ = 1,
    CRACK_REQ,
    PASS_FOUND,
    PASS_NOTFOUND,
    UNKNOWN,
};

typedef struct server_s {
    pthread_mutex_t srv_lock;
    lsp_server* srv_lsp_server;
    struct list_head srv_req_input_list;
    struct list_head srv_req_working_list;
    struct list_head srv_worker_list;
    pthread_t srv_sched_thread;
} server;

typedef struct request_s {
    uint32_t req_connid;
    pthread_mutex_t req_lock;
    struct list_head req_entry;
    char req_msg[1024];
    struct list_head req_worker_list;
    uint32_t req_status; // 0 init, 1 working, 2 finish
    char req_ret[100];
    char req_ret_status; // 0 not found, 1 found;
} request;

typedef struct worker_s {
    uint32_t wk_connid;
    pthread_mutex_t wk_lock;
    struct list_head wk_entry;
    struct list_head wk_req_entry;
    request* wk_req;
    char wk_crack_req[1024];
    char wk_crack_req_ret[100];
    int wk_status; // 0 idle, 1 work, 2 finish, 3 error
} worker;


server* server_create(int port) {
    server* srv = (server*)malloc(sizeof(server));
    srv->srv_lsp_server = lsp_server_create(port);
    LOCK_INIT(&srv->srv_lock);
    INIT_LIST_HEAD(&srv->srv_worker_list);
    INIT_LIST_HEAD(&srv->srv_req_input_list);
    INIT_LIST_HEAD(&srv->srv_req_working_list);
    return srv;
}

void server_clean(server* srv) {
    //lsp_server_close(srv->srv_lsp_server);
    // todo:
    // clean all list
    free(srv);
}

request* request_create(int req_connid, char* payload, int len) {
    request* req = (request*)malloc(sizeof(request));
    req->req_connid = req_connid;
    LOCK_INIT(&req->req_lock);
    INIT_LIST_HEAD(&req->req_entry);
    INIT_LIST_HEAD(&req->req_worker_list);
    req->req_status = 0;
    req->req_ret_status = 0;
    memset(req->req_msg, 0, sizeof(req->req_msg));
    memset(req->req_ret, 0, sizeof(req->req_ret));
    memcpy(req->req_msg, payload, len);
    DEBUG("request_create: req_msg %s", req->req_msg);
    return req;
}

void request_clean(request* req) {
    free(req);
}

void usage() {
    PRINTF("usage: ./server port");
}

void assign_one_req(server* srv, request* req, int worker_maxnum);


void _worker_clean(worker* w) {
    memset(w->wk_crack_req, 0, sizeof(w->wk_crack_req));
    memset(w->wk_crack_req_ret, 0, sizeof(w->wk_crack_req_ret));
    w->wk_status = 0;
}

enum dpc_msg_type dpc_get_msg_type(char* payload, int len) {
    enum dpc_msg_type ret =  UNKNOWN;
    if (len == 0) {
        DEBUG("dpc_get_msg_type: 0 len, no msg type");
        return ret;
    }
    
    switch(payload[0]) {
        case 'j':
        ret = JOIN_REQ;
        break;
        case 'c':
        ret = CRACK_REQ;
        break;
        case 'f':
        ret = PASS_FOUND;
        break;
        case 'x':
        ret = PASS_NOTFOUND;
        break;
        default:
        ret = UNKNOWN;
        DEBUG("dpc_get_msg_type: get UNKNOWN msg");
    }
    return ret;
}

worker* worker_found(server* srv, int worker_connid) {
    worker* w;
    worker* ret = NULL;
    LOCK(&srv->srv_lock);
    list_for_each_entry(w, &srv->srv_worker_list, wk_entry) {
        if (w->wk_connid == worker_connid) {
            ret = w;
            break;
        }
    }
    UNLOCK(&srv->srv_lock);
    return ret;
    return w;
}

void worker_add(server* srv, uint32_t wk_connid) {
    worker* w = (worker *)malloc(sizeof(worker));
    if (w == NULL) {
        DEBUG("work_add: malloc work failed");
        return;
    }
    
    memset(w, 0, sizeof(worker));
    w->wk_connid = wk_connid;
    LOCK(&srv->srv_lock);
    list_add_tail(&w->wk_entry, &srv->srv_worker_list);
    UNLOCK(&srv->srv_lock);
}

void worker_del(server* srv, uint32_t wk_connid) {
    worker* w;
    worker* tmp;
    
    LOCK(&srv->srv_lock);
    list_for_each_entry_safe(w, tmp, &srv->srv_worker_list, wk_entry) {
        if (w->wk_connid == wk_connid) {
            list_del(&w->wk_entry);
            break;
        }
    }
    UNLOCK(&srv->srv_lock);
}

request* request_found(server* srv, uint32_t req_connid) {
    request* req;
    request* ret = NULL;
    
    LOCK(&srv->srv_lock);
    list_for_each_entry(req, &srv->srv_req_input_list, req_entry) {
        if (req->req_connid == req_connid) {
            ret = req;
            break;
        }
    }
    UNLOCK(&srv->srv_lock);
    return ret;    
}

void request_add(server* srv, char* payload, int len, int req_connid) {
    
}


void handle_join_req(server* srv, char* payload, int len, int client_connid) {
    // worker join
    DEBUG("handle_join_req: add a worker, %d", client_connid);
    worker_add(srv, client_connid);
}

uint32_t pass_char2num(char* pass, int len) {
    uint32_t ret, i;
    ret = 0;
    for ( i = 0; i < len; i++) {
        ret += pass[i] - 'a';
        ret *= 26;
    }
    ret /= 26;
    DEBUG("pass_char2num: pass %s, ret %d", pass, ret);
    return ret;
}

void pass_num2char(uint32_t num, char* pass, int len) {
    int i;
    memset(pass, 'a', len + 1);
    pass[len] = '\0';
    for (i = len - 1; i >= 0; i--) {
        pass[i] = 'a' + num % 26;
        num /= 26;
        //DEBUG("pass_num2char: num %d , pass %s, i %d", num, pass, i);
    }
    DEBUG("pass_num2char: num %d, pass %s", num, pass);
}


// four type msg handler 

void handle_crack_req(server* srv, char* payload, int len, int client_connid) {
    request* req;
    
    // init req: add req to srv->srv_req_input_list
    DEBUG("handle_crack_req: add req %s ", payload);
    req = request_create(client_connid, payload, len);
    LOCK(&srv->srv_lock);
    list_add_tail(&req->req_entry, &srv->srv_req_input_list);
    UNLOCK(&srv->srv_lock);
    
    // TODO: use sched
    assign_one_req(srv, req, 10);
}

void check_req_status(server* srv, request* req) {
    uint32_t req_connid;
    lsp_server* lsp_server = srv->srv_lsp_server;
    char* payload;
    int len;
    int finish = 0;
    
    LOCK(&req->req_lock);
    if (req->req_ret_status == 1) {
        // password found
        payload = req->req_ret;
        len = strlen(req->req_ret);
        req_connid = req->req_connid;
        lsp_server_write(lsp_server, payload, len, req_connid);
    } else if(list_empty(&req->req_worker_list) && req->req_ret_status == 0) {
        // password not found
        char* payload = "x";
        len = strlen(payload);
        req_connid = req->req_connid;
        lsp_server_write(lsp_server, payload, len, req_connid);
    }
    if (list_empty(&req->req_worker_list)) {
        finish = 1;   
        list_del(&req->req_entry);
    }
    UNLOCK(&req->req_lock);
    
    if (finish) {
        free(req);
    }
}

void handle_pass_found(server* srv, char* payload, int len, int client_connid) {
    worker* w;
    char* pass;
    char* delim = " ";
    request* req;
    
    w = worker_found(srv, client_connid);
    
    LOCK(&w->wk_lock);
    sprintf(w->wk_crack_req_ret, payload, len);
    w->wk_status = 2;
    req = w->wk_req;
    UNLOCK(&w->wk_lock);
    
    LOCK(&req->req_lock);
    sprintf(req->req_ret, payload, len);
    req->req_ret_status = 1;
    
    LOCK(&w->wk_lock);
    w->wk_status = 0;
    memset(w->wk_crack_req, 0, sizeof(w->wk_crack_req));
    memset(w->wk_crack_req_ret, 0, sizeof(w->wk_crack_req_ret));
    w->wk_req = NULL;
    list_del(&w->wk_req_entry);
    
    UNLOCK(&w->wk_lock);
    
    UNLOCK(&req->req_lock);
    
    check_req_status(srv, req);
}

void handle_pass_notfound(server* srv, char* payload, int len, int client_connid) {
    worker* w;
    char* pass;
    char* delim = " ";
    request* req;
    
    w = worker_found(srv, client_connid);
    
    LOCK(&w->wk_lock);
    w->wk_status = 0;
    req = w->wk_req;
    memset(w->wk_crack_req, 0, sizeof(w->wk_crack_req));
    UNLOCK(&w->wk_lock);
    
    LOCK(&req->req_lock);
    LOCK(&w->wk_lock);
    w->wk_req = NULL;
    list_del(&w->wk_req_entry);
    
    UNLOCK(&w->wk_lock);
    UNLOCK(&req->req_lock);
        
    check_req_status(srv, req);   
}

void assign_one_req(server* srv, request* req, int worker_maxnum) {
    // lock these worker.
    // or lock the server.    
    // compute idle worker
    DEBUG("assign_one_req: crack msg: %s", req->req_msg);
    int worker_count = 0;
    worker* w;
    int get_all_worker = 0;
    LOCK(&srv->srv_lock);
    LOCK(&req->req_lock);
    list_for_each_entry(w, &srv->srv_worker_list, wk_entry) {
        // wk_status 0: idle
        LOCK(&w->wk_lock);
        if (w->wk_status == 0) {
            w->wk_req = req;
            list_add_tail(&w->wk_req_entry, &req->req_worker_list);
            w->wk_status = 1;
            worker_count++;
            if (worker_count > worker_maxnum)
                get_all_worker = 1;
        }
        UNLOCK(&w->wk_lock);
        if (get_all_worker)
            break;
    }
    UNLOCK(&req->req_lock);
    UNLOCK(&srv->srv_lock);
    

    
    // compute sub job.
    uint32_t lower_num, upper_num;
    char* lower;
    char* upper;
    char* hash;
    char* delim = " ";
    uint32_t pass_total_num, pass_per_worker_num;
    int i, len;
    
    strtok(req->req_msg, delim);
    hash = strtok(NULL, delim);
    lower = strtok(NULL, delim);
    upper = strtok(NULL, delim);
    len = strlen(lower);
    
    DEBUG("assign_one_req: hash %s, lower %s upper %s, len %d", hash, lower, upper, len);
    
    
    // no worker
    if (worker_count == 0) {
        DEBUG("assign_one_req:no worker");
        return;
    }
    
    lower_num = pass_char2num(lower, strlen(lower));
    upper_num = pass_char2num(upper, strlen(upper));
    pass_total_num = upper_num - lower_num;
    pass_per_worker_num = pass_total_num / worker_count;
    DEBUG("assign_one_req: lower_num %d, upper_num %d, pass_per_worker_num: %d", lower_num, upper_num, pass_per_worker_num);
    
    // send job.
    char* sub_lower;
    char* sub_upper;
    uint32_t sub_lower_num, sub_upper_num;
    char* space = " ";
    
    sub_lower = (char*)malloc(len + 1);
    sub_upper = (char*)malloc(len + 1);
    memcpy(sub_lower, lower, len + 1);
    sub_lower_num = pass_char2num(sub_lower, len);
    
    list_for_each_entry(w, &req->req_worker_list, wk_req_entry) {
        // get upper
        sub_upper_num = sub_lower_num + pass_per_worker_num;
        DEBUG("assign_one_req: sub_upper_num %d", sub_upper_num);
        pass_num2char(sub_upper_num, sub_upper, len);
        // gen worker crack req
        int offset = 0;
        sprintf(w->wk_crack_req + offset, "c ", 2);
        offset += 2;
        sprintf(w->wk_crack_req + offset, hash, strlen(hash));
        offset += strlen(hash);
        sprintf(w->wk_crack_req + offset, space, 1);
        offset += 1;
        sprintf(w->wk_crack_req + offset, sub_lower, len);
        offset += len;
        sprintf(w->wk_crack_req + offset, space, 1);
        offset += 1;
        sprintf(w->wk_crack_req + offset, sub_upper, len);
        offset += len;
        w->wk_crack_req[offset] = '\0';
        
        DEBUG("handle_crack_req: worker %d crack req %s", w->wk_connid, w->wk_crack_req);
        
        
        // send crack req to worker
        DEBUG("handle_cracke_req: send work %d crack msg %s", w->wk_connid, w->wk_crack_req);
        lsp_server_write(srv->srv_lsp_server, w->wk_crack_req, strlen(w->wk_crack_req), w->wk_connid);
        
        sub_lower_num = sub_upper_num + 1;
    }
    
    free(sub_lower);
    free(sub_upper);
}

// TODO:
void sched_thread_run(void* context) {
    server* srv = (server*)context;
}

// reschedule req:
// 1. sched req that not had worker yield
// 2. check work error, and resign one





int main(int argc, char* argv[]) {
    lsp_server* lsp_srv;
    server* srv;
    int port;
    char payload[1000];
    uint32_t client_connid;
    enum dpc_msg_type dpc_msg_type;
    int read_bytes;
    
    
    if (argc != 2) {
        usage();
        exit(-1);
    }
    
    port = atoi(argv[1]);
    
    srv = server_create(port);
    lsp_srv = srv->srv_lsp_server;
    if (srv == NULL) {
        PRINTF("server: create server failed");
    }
    
    
    while (1) {
        DEBUG("server: read dpc msg");
        read_bytes = lsp_server_read(lsp_srv, payload, &client_connid);
        
        // new connid.
        if (read_bytes == 0)
            continue;
        
        dpc_msg_type = dpc_get_msg_type(payload, read_bytes);
        switch (dpc_msg_type) {
        case JOIN_REQ:
            handle_join_req(srv, payload, read_bytes, client_connid);
            break;
        case CRACK_REQ:
            handle_crack_req(srv, payload, read_bytes, client_connid);
            break;
        case PASS_FOUND:
            handle_pass_found(srv, payload, read_bytes, client_connid);
            break;
        case PASS_NOTFOUND:
            handle_pass_notfound(srv, payload,read_bytes, client_connid);
            break;
        case UNKNOWN:
            DEBUG("srever: not unkown msg");
        default:
            DEBUG("server: not happen here ");
        }
    }
}


#endif