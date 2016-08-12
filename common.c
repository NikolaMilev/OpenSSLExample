#include "common.h"

void handle_error(const char *file, int lineno, const char *msg)
{
	fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
	ERR_print_errors_fp(stderr);
	exit(-1);
}
void init_OpenSSL(void)
{
	// SSL_library_init() does initialization of the SSL library, 
	// adding various algorithms used in SSL
	if (!SSL_library_init())
	{
		fprintf(stderr, "** OpenSSL initialization failed!\n");
		exit(-1);
	}
	//Loads error strings for various SSL functions
	SSL_load_error_strings();
}

//Not sure if this is good idea! Have to do some research
int seed_prng(int bytes)
{
	//Seeds PRNG (pseudo random number generator) with the contents of the /dev/urandom file
	if (!RAND_load_file("/dev/urandom", bytes))
	{
		return 0;
	}

	return 1;
}

int verify_callback(int ok, X509_STORE_CTX *store)
{
	char data[DATA_SIZE_];
	if (!ok)
	{
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int depth = X509_STORE_CTX_get_error_depth(store);
		int err = X509_STORE_CTX_get_error(store);
		fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
		X509_NAME_oneline(X509_get_issuer_name(cert), data, DATA_SIZE_);
		fprintf(stderr, " issuer = %s\n", data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, DATA_SIZE_);
		fprintf(stderr, " subject = %s\n", data);
		fprintf(stderr, " err %i:%s\n", err,
		X509_verify_cert_error_string(err));
	}
	return ok;
}

long post_connection_check(SSL *ssl, char *host)
{
	X509 *cert;
	X509_NAME *subj;
	char data[DATA_SIZE_];
	//int extcount;
	int ok = 1;
	
	//Get peer certificate retrieves 
	if (!(cert = SSL_get_peer_certificate(ssl)) || !host)
	{
		if (cert)
		{
			X509_free(cert);
		}
		return X509_V_ERR_APPLICATION_VERIFICATION;
	}
	// if ((extcount = X509_get_ext_count(cert)) > 0)
	// {
	// 	int i;

	// 	for (i = 0; i < extcount; i++)
	// 	{
	// 		const char *extstr;
	// 		X509_EXTENSION *ext;
	// 		ext = X509_get_ext(cert, i);
	// 		extstr = OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
	// 		if (!strcmp(extstr, "subjectAltName"))
	// 		{
	// 			int j;
	// 			unsigned char *data;
	// 			STACK_OF(CONF_VALUE) *val;
	// 			CONF_VALUE *nval;
	// 			const X509V3_EXT_METHOD *meth;
	// 			if (!(meth = X509V3_EXT_get(ext)))
	// 			{
	// 				break;
	// 			}
	// 			data = ext->value->data;
	// 			val = meth->i2v(meth,(meth->d2i(NULL, (const unsigned char **)(&data), ext->value->length)), NULL);
	// 			for (j = 0; j < sk_CONF_VALUE_num(val); j++)
	// 			{
	// 				nval = sk_CONF_VALUE_value(val, j);
	// 				if (!strcmp(nval->name, "DNS") && !strcmp(nval->value, host))
	// 				{
	// 					ok = 1;
	// 					break;
	// 				}
	// 			}
	// 		}
	// 		if (ok)
	// 		{
	// 			break;
	// 		}
	// 	}
	// }
	if (!ok && (subj = X509_get_subject_name(cert)) && X509_NAME_get_text_by_NID(subj, NID_commonName, data, DATA_SIZE_) > 0)
	{
		data[DEFAULT_DEPTH_ - 1] = 0;
		if (strcasecmp(data, host) != 0)
		{
			if (cert)
			{
				X509_free(cert);
			}
			
			return X509_V_ERR_APPLICATION_VERIFICATION;
		}
	}
	X509_free(cert);
	return SSL_get_verify_result(ssl);
}