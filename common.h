#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>


#define PORT "8080"
#define SERVER "localhost"
#define CLIENT "localhost"
#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

//Do not confuse with SSL_METHOD ; TLSv1_method() is also a viable option here
#define SSL_METHOD_ SSLv23_method()
#define SEED_PRNG_() seed_prng(30) 

#define DEFAULT_DEPTH_ 4

#define DATA_SIZE_ 256


void handle_error(const char *file, int lineno, const char *msg) ;
void init_OpenSSL(void) ;
int seed_prng(int bytes) ;
int verify_callback(int ok, X509_STORE_CTX *store) ;
long post_connection_check(SSL *ssl, char *host) ;