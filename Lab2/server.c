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
// #include "lab2server.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#define CA_LIST "568ca.pem"
#define KEYFILE "bob.pem"
#define PASSWORD "password"
#define DHFILE "568ca.pem"
#define CLIENT_CN "Alice's Client"
#define CLIENT_EMAIL "ece568alice@ecf.utoronto.ca"
#define BUFSIZZ 255

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

/* Some code based off of Eric Rescorla's "An Introduction to
 * OpenSSL Programming" Parts I and II
 *
 * To keep things simple, server may exit on error after printing 
 * error string
 */

// should move these to lab2common.h
BIO *bio_err=0;
static char *pass;

/* A simple error and exit routine*/
int err_exit(char *string)
{
    fprintf(stderr,string);
    exit(0);
}

/* Print SSL errors and exit*/
int berr_exit(char *string)
{
    BIO_printf(bio_err,string);
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

void destroy_ctx(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx);
}

SSL_CTX *initialize_ctx(char *keyfile, char *password)
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
      // method = SSLv2_method();
      method = SSLv23_method();
      ctx = SSL_CTX_new(method);

      /* Load our keys and certificates */
      if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile))) {
            berr_exit("Can't read certificate file\n");
      }
      
      pass = password;
      SSL_CTX_set_default_passwd_cb(ctx, password_cb);

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

// should move these to lab2server.c
// #define CIPHERS "SSLv2:SSLv3:TLSv1:!SHA1"
#define CIPHERS "SSLv2:SSLv3:TLSv1"

/*
 * Print info from the client's certificate chain
 */
void check_client_cert(SSL *ssl)
{
    X509 *peer;
    char peer_CN[256];
    char email[256];
    
    /* These two checks might be redundant...
     * Verify certificate 
     */
    if(SSL_get_verify_result(ssl) != X509_V_OK) {
        berr_exit("Certificate doesn't verify\n");
    }
    
    /* Check the cert chain. The chain length is
       automatically checked by OpenSSL when we set
       the verify depth in the ctx */

    /* need both SSL_get_verify_result and SSL_get_peer_certificate 
     * to ensure that peer certificate was presented
     */
    peer = SSL_get_peer_certificate(ssl);

    /* Read the common name and email */
    // apparently the below method is legacy, should use newer function
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
                              NID_commonName,
                              peer_CN,
                              256);
    
    printf("Peer CN: %s\n", peer_CN);

    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
                              NID_pkcs9_emailAddress,
                              email,
                              256);

    printf("Peer email: %s\n", email);
    
    /* print the client info */
    printf(FMT_CLIENT_INFO, peer_CN, email);

}

/* what does this function do? */
void load_dh_params(SSL_CTX *ctx, char *file)
{
    DH *ret=0;
    BIO *bio;

    if ((bio=BIO_new_file(file,"r")) == NULL)
      berr_exit("Couldn't open DH file");

    ret=PEM_read_bio_DHparams(bio,NULL,NULL,
      NULL);
    BIO_free(bio);
    if(SSL_CTX_set_tmp_dh(ctx,ret)<0)
      berr_exit("Couldn't set DH parameters");
}

/* 
 * Server (run by Bob) specification
 *      Server must support:
 *          SSLv2, SSLv3, TLSv1
 *          all cipher suites available for SSLv2, SSLv3 and TLSv1
 *          should only communicate with clients with a valid certificate
 *              signed by the proper CA
 *          if client has valid cert, print CN and email as well as the
 *              client request and server response
 *          Shutdown connection properly
 *          Report when client does not shutdown correctly
 */
int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  
  BIO *sbio;
  SSL_CTX *ctx;
  SSL *ssl;
  int r;

  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  /* Build SSL context */
  ctx = initialize_ctx(KEYFILE, PASSWORD);
  load_dh_params(ctx, DHFILE);

  /* set cipher list */
  SSL_CTX_set_cipher_list(ctx, CIPHERS);
  
  /* authenticate client by requiring valid certificate */
  SSL_CTX_set_verify(ctx, 
                     SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     NULL);

  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    else {
      char buf[BUFSIZZ];
      int len=0;
      char *answer = "42";
      // BIO *io, *ssl_bio;
      int answer_len;

      sbio = BIO_new_socket(s,BIO_NOCLOSE);
      ssl = SSL_new(ctx);
      SSL_set_bio(ssl, sbio, sbio);

      /* SSL server-side handshake */
      if((r=SSL_accept(ssl) <= 0)) { // blocking sockets
        /* client did not present certificate or 
         * cert not signed by proper CA
         * instructed by SSL_CTX_set_verify flags
         */
        berr_exit(FMT_ACCEPT_ERR);
      }

      /* At this point all the server knows is the client possessed
       * the private key corresponding to *some* valid cert
       * To keep it simple, no access control list
       * But there should be one to check against client name (Alice)
       */
      check_client_cert(ssl);

      /* serve client */
      while(1) {
          r = SSL_read(ssl, buf, BUFSIZZ);
          printf("read : %d\n", r);
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
                  default:
                    berr_exit("SSL read problem\n");
            }
          printf("len: %d\n", len);

          /* Workaround to determine when to stop reading 
           * A bit wonky, but necessary since there might be buffering so
           * SSL_read does not guarantee the entire client message will be 
           * read in a single go
           * Keep going until buf contains the entire client message, which
           * is known for this lab
           */
          char save = buf[len];
          buf[len] = '\0';
          if (!strcmp(buf,"What's the question?")) {
            break;
          }
          buf[len] = save;
      }

      answer_len = strlen(answer);
      if (answer_len > 255) {
         answer_len = 255;
      }

      r = SSL_write(ssl, answer, answer_len);
      printf("write: %d\n", r);
      switch(SSL_get_error(ssl,r)) {
        case SSL_ERROR_NONE:
            if(answer_len != r) // all-or-nothing
                err_exit("Incomplete write!\n");
            break;
        default:
            berr_exit("SSL write problem\n");
      }

      /* buffered I/O 
       * can't figure out why BIO_gets can't read anything (returns 0)
       * suspect it has something to do with new lines CLRF or LF
       * which is particular to HTTP and others
       */
      /* io = BIO_new(BIO_f_buffer());
      ssl_bio = BIO_new(BIO_f_ssl());
      BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
      BIO_push(io, ssl_bio);

      while(1){
        r = BIO_gets(io, buf, BUFSIZZ);
        fprintf(stderr, "r: %d\n", r);
        int x=SSL_get_error(ssl, r);
        fprintf(stderr, "x: %d\n", x);
        switch(x) {
            case SSL_ERROR_NONE:
                len += r;
                break;
            case SSL_ERROR_ZERO_RETURN:
                goto shutdown;
            default:
                berr_exit("SSL read problem\n");
        }
        char save = buf[len];
        buf[len] = '\0';
        fprintf(stderr, "len: %d\n", len);
        fprintf(stderr, "r: %d\n", r);
        fprintf(stderr, "buf: %s\n", buf);
        if (!strcmp(buf,"What's the question?")) {
            break;
        }
        buf[len] = save;
      }

      if((r=BIO_puts(io, answer)) <= 0) {
        err_exit("Write error\n");
      }

      if((r=BIO_flush(io) < 0)) {
        err_exit("Error flushing BIO\n");
      } */
      

    shutdown:
      r = SSL_shutdown(ssl);
      
      if(!r) {
        /* If we called SSL_shutdown() first then
           we always get return value of '0'. In
           this case, try again, but first send a
           TCP FIN to trigger the other side's
           close_notify*/
        shutdown(s,1);
        r=SSL_shutdown(ssl);
      }

      switch(r) {
        case 1:
          break; /* Success */
        case 0:
        case -1:
        default:
          // couldn't get client to close properly
          berr_exit(FMT_INCOMPLETE_CLOSE);
          // fprintf(stderr, FMT_INCOMPLETE_CLOSE);
          // berr_exit("Shutdown failed\n");
      }

      SSL_free(ssl);
      close(sock);
      close(s);

      /* Print the client request and server response */
      printf(FMT_OUTPUT, buf, answer);

      return 0;
      
      /*Child code*/
      /* int len;
      char buf[256];
      char *answer = "42";

      len = recv(s, &buf, 255, 0);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      send(s, answer, strlen(answer), 0);
      close(sock);
      close(s);
      return 0;
      */
    }
  }
  
  destroy_ctx(ctx);
  close(sock);
  return 1;
}
