$CC=gcc
$CFLAGS=-O0 -g2
all: sample_client sample_server
	
sample_client: 
	$C -O0 -g2 -o sample_client sample_client.c lsp_client.c lsp_common.c lsp.pb-c.c -lprotobuf-c

sample_server:
	$C -O0 -g2 -o sample_server sample_server.c lsp_server.c lsp_common.c lsp.pb-c.c -lprotobuf-c
	
clean:
	rm -rf sample_client sample_server
