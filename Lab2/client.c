#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// #include "lab2common.h"
// #include "lab2client.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#define CA_LIST "568ca.pem"
// modify the KEYFILE macro to trigger "no certificate returned"
#define KEYFILE "alice.pem"
#define PASSWORD "password"
#define SERVER_CN "Bob's Server"
#define SERVER_EMAIL "ece568bob@ecf.utoronto.ca"
#define BUFSIZZ 255

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

/* Some code based off of Eric Rescorla's "An Introduction to
 * OpenSSL Programming" Parts I and II
 *
 * To keep things simple, client may exit on error after printing 
 * error string
 */

static int require_server_auth = 1;
BIO *bio_err=0;
static char *pass;

// should move these into lab2common.c

/* A simple error and exit routine*/
int err_exit(char *string)
{
    fprintf(stderr, string);
    exit(0);
}

/* Print SSL errors and exit*/
int berr_exit(char *string)
{
    BIO_printf(bio_err, string);
    ERR_print_errors(bio_err);
    exit(0);
}

/*The password code is not thread safe*/
static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
{
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
}

/* dummy handler */
static void sigpipe_handle(int x) {
}

// create overloaded function without ability to set options (used by server)
// check out options defined by macros in ssl.h
SSL_CTX *initialize_ctx(char *keyfile, char *password, long options)
{
      const SSL_METHOD *method;
      SSL_CTX *ctx;

      if(!bio_err) {
            /* Global system initialization */
            SSL_library_init();
            SSL_load_error_strings();

            /* An error write context */
            bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
      }

      /* Set up a SIGPIPE handler */
      signal(SIGPIPE, sigpipe_handle);

      /* Create context 
       * SSLv23_method() enables SSLv2, SSLv3, and TLSv1
       */
      method = SSLv23_method();
      ctx = SSL_CTX_new(method);
      SSL_CTX_set_options(ctx, options);

      /* Load our keys and certificates */
      if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile))) {
            berr_exit("Can't read certificate file\n");
      }
      
      pass = password;
      SSL_CTX_set_default_passwd_cb(ctx, password_cb);

      // comment out this line to trigger "peer did not return a certificate"
      if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM))) {
            berr_exit("Can't read key file\n");
      }

      /* Load the CAs we trust */
      if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST, 0))) {
            berr_exit("Can't read CA list\n");
      }
#if (OPENSSL_VERSION_NUMBER < 0x0090600fL)
      SSL_CTX_set_verify_depth(ctx,1);
#endif
      return ctx;
}

void destroy_ctx(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx);
}

// should move these to lab2client.c

/*
 * Check that the common name matches the host name and
 * the email address of server certificate subject is correct
 * Check the server's certificate chain
 */
void check_cert(SSL *ssl, char *host, char *email)
{
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];
    char issuer[256];
    
    /* Verify certificate */
    if(SSL_get_verify_result(ssl) != X509_V_OK) {
        berr_exit(FMT_NO_VERIFY);
    }
   
    /* Check the cert chain. The chain length is
       automatically checked by OpenSSL when we set
       the verify depth in the ctx */

    /* need both SSL_get_verify_result and SSL_get_peer_certificate 
     * to ensure that peer certificate was presented
     */
    peer = SSL_get_peer_certificate(ssl);

    /* Check the common name */
    // apparently the below method is legacy, should use newer function
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
                              NID_commonName,
                              peer_CN,
                              256);

    /* 
    X509_NAME_ENTRY *e;
    int lastpos = X509_NAME_get_index_by_NID(X509_get_subject_name(peer),
                            NID_commonName,
                            0);
    if (lastpos != -1) {
        e = X509_NAME_get_entry(X509_get_subject_name(peer), lastpos);
    }
    */
    
    printf("Peer CN: %s\n", peer_CN);
    
    if(strcmp(peer_CN, SERVER_CN)) {
        err_exit(FMT_CN_MISMATCH);
    }

    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
                              NID_pkcs9_emailAddress,
                              peer_email,
                              256);

    printf("Peer email: %s\n", peer_email);

    if(strcmp(peer_email, email)) {
        err_exit(FMT_EMAIL_MISMATCH);
    }
    
    /* at this point, CN and Email are correct
     * print the server info
     */

    X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),
                              NID_commonName,
                              issuer,
                              256);

    printf("Certificate issuer: %s\n", issuer);

    printf(FMT_SERVER_INFO, peer_CN, peer_email, issuer);

}

/*
 * Client (run by Alice) specification: 
 *      Only communicate with:
 *  servers using SSLv3 or TLSv1
 *  a protocol that uses the SHA1 hash function
 *  Bob's Server by checking that the Common Name of the server matches
 *      "Bob's Server" and the email address matches "ece568bob@ecf.utoronto.ca"
 *  
 *      Shutdown SSL connection correctly or report otherwise
 *
 *  for simplicity, client will exit on error after printing error string
 */
int main(int argc, char **argv)
{
  int len=0, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";

  SSL *ssl;
  SSL_CTX *ctx;
  BIO *sbio;
  int ret;
  int r;
  int secret_len;
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  /* build SSL context */
  ctx = initialize_ctx(KEYFILE, PASSWORD, SSL_OP_NO_SSLv2);
  
  /* set cipher list */
  SSL_CTX_set_cipher_list(ctx, "SHA1");
  
  /* Connect the SSL socket 
   * the SSL struct contains current options in ctx
   * build BIO object on socket and then SSL object on BIO
   */
  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE);
  SSL_set_bio(ssl, sbio, sbio);
  
  /* try to connect and diagnose errors if unsuccessful */
  if((ret = SSL_connect(ssl)) <= 0) { // SSL handshake with blocking sockets
    fprintf(stderr, "ret: %d\n", ret);
    int error = SSL_get_error(ssl, ret);
    fprintf(stderr, "error: %d\n", error);
    berr_exit(FMT_CONNECT_ERR);
  }
  if(require_server_auth) {
    /* Could alternatively use SSL_CTX_set_verify to check cert before 
     * handshake completes
     * Right now, client will behave such that the server will see a 
     * generic error if its cert is bad
     */
    check_cert(ssl, SERVER_CN, SERVER_EMAIL);
  }
  
  /* at this point, the certificate information has been deemed correct */
  
  /* restrict message length to 255 characters at most */
  secret_len = strlen(secret);
  if (secret_len > 255) {
    secret_len = 255;
  }
  
  /* send encrypted data to server 
   * during debugging found out that even if the server exits
   * the SSL_write can succeed and it's not until SSL_read
   * where an error will appear
   */
  r = SSL_write(ssl, secret, secret_len);
  switch(SSL_get_error(ssl,r)) {
    case SSL_ERROR_NONE:
      if(secret_len != r) // all-or-nothing
        err_exit("Incomplete write!\n");
      break;
    default:
        berr_exit("SSL write problem\n");
  }
  
  
  /* receive encrypted data from server */
  while(1) {
    /* read up to BUFSIZZ chars (255) */
    r = SSL_read(ssl, buf, BUFSIZZ);
    printf("read: %d\n", r);
    int err = SSL_get_error(ssl, r);
    printf("read error code: %d\n", err);
    switch(err) {
        case SSL_ERROR_NONE: // 0
          /* keep track of where string ends over possible multiple read iterations */
          len += r;
          break;
          case SSL_ERROR_ZERO_RETURN: // 6
            /* for SSLv3 and TLSv1 the connection has been closed cleanly */
            goto shutdown;
          case SSL_ERROR_SYSCALL: // 5
            /* received FIN before a close_notify, premature close */
            // fprintf(stderr, "SSL Error: Premature close\n");
            err_exit(FMT_INCORRECT_CLOSE);
          default:
            berr_exit("SSL read problem\n");
    }
    printf("len: %d\n", len);
    // fwrite(buf,1,len,stdout);
  }

  shutdown:
    // exit(0);
    r=SSL_shutdown(ssl);
    switch(r) {
        case 1:
            break; /* Success */
        case 0:
        case -1:
        default:
            berr_exit("Shutdown failed\n");
    }

  SSL_free(ssl);
  
  // send(sock, secret, strlen(secret),0);
  // len = recv(sock, &buf, 255, 0);
  // buf[len]='\0';
  
  buf[len] = '\0';
  
  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);
  
  // since close flag set, socket is shut down and closed when BIO freed
  
  
  /* clean up */
  
  destroy_ctx(ctx);
  close(sock);

  return 1;
}
