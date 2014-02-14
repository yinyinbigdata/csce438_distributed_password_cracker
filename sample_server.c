#include "api.h"
#include "lsp.pb-c.h"

int main(int argc, char* argv[]) {
    lsp_server* myserver = lsp_server_create(0);
    
    uint8_t payload[4096];
    uint32_t returned_id;
    int bytes_read;
    
    for(;;) {
        // wait for echo client to send something
        int bytes = lsp_server_read(myserver, payload, &returned_id);
        
        if (bytes == 0) {
            continue;
        }
        
        // Echo it right back
        lsp_server_write(myserver, payload, bytes, returned_id);
    }
}
