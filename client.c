#include "common.h"

#define BUF_SIZE_ 80

#define CERTFILE "certificates/client.cert.pem"
#define KEYFILE "certificates/client.key.pem"

#define CAFILE "certificates/ca-chain.cert.pem"
#define CADIR NULL

SSL_CTX *setup_client_ctx(void)
{
	SSL_CTX *ctx;
	ctx = SSL_CTX_new(SSL_METHOD_);

	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
	{	
		int_error("Error loading CA file and/or directory");
	}
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		int_error("Error loading default CA file and/or directory");
	}
	if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
	{
		int_error("Error loading certificate from file");
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) != 1)
	{
		int_error("Error loading private key from file");
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	SSL_CTX_set_verify_depth(ctx, DEFAULT_DEPTH_);

	return ctx;
}

int do_client_loop(SSL *ssl)
{
	int err, nwritten;
	char buf[BUF_SIZE_];
	for (;;)
	{
		if (!fgets(buf, sizeof(buf), stdin))
		{
			break;
		}
		//printf("ucitao: %s\n", buf);
		for (nwritten = 0; nwritten < sizeof(buf); nwritten += err)
		{

			err = SSL_write(ssl, buf + nwritten, strlen(buf) - nwritten);
			if (err <= 0)
			{
				return 0;
			}
			else
			{
				printf("Sent: %s\n", buf);
			}
		}

	}
	return 1;
}

int main(int argc, char *argv[])
{
	BIO *conn;
	SSL *ssl;
	SSL_CTX *ctx; 
	long err;
	
	init_OpenSSL();
	SEED_PRNG_();

	ctx = setup_client_ctx();

	conn = BIO_new_connect(SERVER ":" PORT);
	if (!conn)
	{
		int_error("Error creating connection BIO");
	}
	if (BIO_do_connect(conn) <= 0)
	{
		int_error("Error connecting to remote machine");
	}
	if (!(ssl = SSL_new(ctx)))
	int_error("Error creating an SSL context");
	SSL_set_bio(ssl, conn, conn);
	if (SSL_connect(ssl) <= 0)
	{
		int_error("Error connecting SSL object");
	}
	if ((err = post_connection_check(ssl, SERVER)) != X509_V_OK)
	{
		fprintf(stderr, "-Error: peer certificate: %s\n",X509_verify_cert_error_string(err));
		int_error("Error checking SSL object after connection");
	}
	fprintf(stderr, "SSL Connection opened\n");
	if (do_client_loop(ssl))
	{
		SSL_shutdown(ssl);
	}
	else
	{
		SSL_clear(ssl);
	}
	fprintf(stderr, "SSL Connection closed\n");
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	return 0;
}