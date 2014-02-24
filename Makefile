$CC=gcc
$CFLAGS=-O0 -g2
all: sample_client sample_server request server worker
	
sample_client: 
	$C -O0 -g2 -o sample_client sample_client.c lsp_client.c lsp_common.c lsp.pb-c.c -lprotobuf-c

sample_server:
	$C -O0 -g2 -o sample_server sample_server.c lsp_server.c lsp_common.c lsp.pb-c.c -lprotobuf-c
	
request:
	$C -O0 -g2 -o request request.c lsp_client.c lsp_common.c lsp.pb-c.c -lprotobuf-c

server:
	$C -O0 -g2 -o server server.c lsp_server.c lsp_common.c lsp.pb-c.c -lprotobuf-c -lpthread
	
worker:
	$C -O0 -g2 -o worker worker.c lsp_client.c lsp_common.c lsp.pb-c.c -lprotobuf-c -lssl
	
clean:
	rm -rf sample_client sample_server request server worker
	