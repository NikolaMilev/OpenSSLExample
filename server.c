#include "common.h"
#include <signal.h>

#define BUF_SIZE_ 80

//If the key and the certificate are in the same file, these two can be the same
#define CERTFILE "certificates/server.cert.pem"
#define KEYFILE "certificates/server.key.pem"

//One of the two values below can be NULL but not both
#define CAFILE "certificates/ca-chain.cert.pem"
#define CADIR NULL


static void intsig(int signo) 
{
	printf("\npoyy\n");
	//signal(SIGINT, intsig);
	fflush(stdout);	
	//exit(EXIT_FAILURE);
}

SSL_CTX *setup_server_ctx(void)
{
	SSL_CTX *ctx;
	
	// This specifies that either SSL or TLS can be used
	// Later, we will "filter" out SSLv2
	ctx = SSL_CTX_new(SSL_METHOD_);

	// if(signal(SIGINT, intsig) == SIG_ERR)
	// {
	// 	printf("\nError setting signal!\n");

	// }

	// NULL return value indicates a failure in creation of SSL_CTX object
	if(ctx == NULL)
	{
		int_error("The creation of a new SSL_CTX object failed.");
	}
	SSL_CTX_set_options(ctx, SSL_CTX_FLAGS_);

	// These two functions are used to load trusted CAs
	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
	{
		int_error("Error loading CA file and/or directory");
	}
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		int_error("Error loading default CA file and/or directory");
	}

	// This loads a certificate from a file
	if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
	{
			int_error("Error loading certificate from file");
	}
	// This loads a private key (in our code, from the same file but I think that it is not necessary)
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) != 1)
	{
			int_error("Error loading private key from file");
	}
	// Setting the verify options for ctx context
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	// Setting the maximum allowed depth for CA verification
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
		

	} while (err > 0);

	fwrite(buf, sizeof(char), nread, stdout);
	// SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN != 0 indicate that the shutdown notification
	// was sent from the peer (in this case, the client)
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
	// As I figured, SSL_shutdown is a clean way to go but SSL_clear 
	// will force the closing of the communication if it wasn't closed cleanly
	// Both will keep the ssl object ready to be used again

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


	//This call does the setup of the server context (see the functiont for more info)
	ctx = setup_server_ctx();

	// Creates BIO and sets the accept port
	acc = BIO_new_accept(PORT);
	if (!acc)
	{
		int_error("Error creating server socket");
	}
	//The first call to BIO_do_accept() binds to the given port 
	if (BIO_do_accept(acc) <= 0)
	{
		int_error("Error binding server socket");
	}
	for (;;)
	{
		//The second BIO_do_accept() call listens on the acc BIO 
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

