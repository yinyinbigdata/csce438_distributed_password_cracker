#include "api.h"
#include "lsp.pb-c.h"


int main(int argc, char * argv[]) {
    lsp_client* myclient = lsp_client_create("127.0.0.1", LSPPORT);  
    // payload of the LSP packet
    char message[] = "ilovethiscoursealready";
    // receive buffer
    uint8_t buffer[4096];
    
    lsp_client_write(myclient, (void *)message, strlen(message));   

    DEBUG("sampel_client: begin read");
    int bytes_read = lsp_client_read(myclient, buffer);
    
    // Print the received LSP protocol payload;
    puts(buffer);
    
    //test more packet
    int i, count = 10;
    char count_message[40];
    uint8_t count_buffer[4096];
    int count_bytes_read;
    for (i = 2; i < count; i++) {
        memset(count_message, 0, sizeof(count_message));
        sprintf(count_message, "seq count %d", i);
        lsp_client_write(myclient, (void*)count_message, strlen(message));
        
        count_bytes_read = lsp_client_read(myclient, count_buffer);
        
        puts(count_buffer);
    }
    
   lsp_client_close(myclient);
}