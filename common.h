//#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>


#define PORT "8080"
#define SERVER "localhost" 	//"192.168.10.146" - PI
#define CLIENT "localhost" 	//"192.168.10.132" - laptop
#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

// Do not confuse with SSL_METHOD ; TLSv1_method() is also a viable option here
// There are others, also. This should be discussed later
// Take a look at this: https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_new.html
#define SSL_METHOD_ SSLv23_method()
#define SEED_PRNG_() seed_prng(30) 

// When doing the final setting up, take a look at the SSL_CTX_set_options man page to see available options!
// SSL_OP_NO_SSLvN forbids the using of SSLvN (here, we force TLS connection)
// SSL_OP_NO_COMPRESSION means that compression is not used, even if available 
// Reason is security, for example: http://security.stackexchange.com/questions/20216/should-i-disable-ssl-compression-because-of-crime
#define SSL_CTX_FLAGS_ SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION

// Default max depth for verifying the certificate chain. If the chain is longer than 4  (not including the initial)
// then the verification will fail
#define DEFAULT_DEPTH_ 4

//Just a default buffer size
#define DATA_SIZE_ 256


void handle_error(const char *file, int lineno, const char *msg) ;
void init_OpenSSL(void) ;
int seed_prng(int bytes) ;
int verify_callback(int ok, X509_STORE_CTX *store) ;
long post_connection_check(SSL *ssl, char *host) ;