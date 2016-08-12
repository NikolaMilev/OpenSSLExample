 #include "common.h"


#define BUF_SIZE_ 80

#define CERTFILE "certificates/server.cert.pem"
#define KEYFILE "certificates/server.key.pem"

#define CAFILE "certificates/ca-chain.cert.pem"
#define CADIR NULL


SSL_CTX *setup_server_ctx(void)
{
	SSL_CTX *ctx;

	//This specifies that either SSL or TLS can be used
	//Later, we will "filter" out SSLv2
	ctx = SSL_CTX_new(SSLv23_method());
	
	//These two functions are used to load trusted CAs
	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
	{
		int_error("Error loading CA file and/or directory");
	}
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		int_error("Error loading default CA file and/or directory");
	}
	
	//This loads a certificate from a file
	if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
	{
			int_error("Error loading certificate from file");
	}
	//This loads a private key (in our code, from the same file but I think that it is not necessary)
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) != 1)
	{
			int_error("Error loading private key from file");
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	SSL_CTX_set_verify_depth(ctx, DEFAULT_DEPTH_);

	return ctx;
}

int do_server_loop(SSL *ssl)
{
	int err, nread;
	char buf[BUF_SIZE_];
	//I think that this reading should be redone 'cause there's something wrong
	do
	{
		for (nread = 0; nread < sizeof(buf) - 1; nread += err)
		{
			err = SSL_read(ssl, buf + nread, sizeof(buf) - nread);
			printf("read %d bytes\n", err);
			if (err <= 0)
			{
				break;
			}
		}
		fwrite(buf, sizeof(char), nread, stdout);

	} while (err > 0);
	return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}


void server_part(SSL *ssl)
{
	long err;
	//accepting connection from ssl object (structure)
	if (SSL_accept(ssl) <= 0)
	{
		int_error("Error accepting SSL connection");
	}
	if ((err = post_connection_check(ssl, CLIENT)) != X509_V_OK)
	{
		fprintf(stderr, "-Error: peer certificate: %s\n",
		X509_verify_cert_error_string(err));
		int_error("Error checking SSL object after connection");
	}
	fprintf(stderr, "SSL Connection opened\n");
	//As I figured, SSL_shutdown is a clean way to go but SSL_clear 
	//will force the closing of the communication if it wasn't closed cleanly
	if (do_server_loop(ssl))
	{
		//See this https://www.openssl.org/docs/manmaster/ssl/SSL_shutdown.html
		SSL_shutdown(ssl);
	}
	else
	{
		// https://www.openssl.org/docs/manmaster/ssl/SSL_clear.html
		SSL_clear(ssl);
	}
	fprintf(stderr, "SSL Connection closed\n");
	SSL_free(ssl);	
}


int main(int argc, char *argv[])
{
	BIO *acc, *client;
	SSL *ssl;
	SSL_CTX *ctx;

	init_OpenSSL();

	//This is my function, gotta investigate it and see what should be there (maybe I got it right?)
	SEED_PRNG_();


	ctx = setup_server_ctx();
	acc = BIO_new_accept(PORT);
	if (!acc)
	{
		int_error("Error creating server socket");
	}
	if (BIO_do_accept(acc) <= 0)
	{
		int_error("Error binding server socket");
	}
	for (;;)
	{
		if (BIO_do_accept(acc) <= 0)
		{
			int_error("Error accepting connection");
		}
		client = BIO_pop(acc);
		if (!(ssl = SSL_new(ctx)))
		{
			int_error("Error creating SSL context");
		}
		SSL_set_bio(ssl, client, client);
		server_part(ssl);
	}
	SSL_CTX_free(ctx);
	BIO_free(acc);
	return 0;
}