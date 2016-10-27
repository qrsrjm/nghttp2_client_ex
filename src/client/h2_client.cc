//: ----------------------------------------------------------------------------
//: \file:    nghttp2_client_ex.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    02/20/2016
//: ----------------------------------------------------------------------------

//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <inttypes.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif /* HAVE_NETDB_H */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>


// -------------------------------------------------------------------
// TODO RPM ADDED begin
// -------------------------------------------------------------------
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
// -------------------------------------------------------------------
// TODO RPM ADDED end
// -------------------------------------------------------------------

#include "nghttp2/nghttp2.h"
#include "support.h"

#include <getopt.h> // For getopt_long
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

//: ----------------------------------------------------------------------------
//: Constants
//: ----------------------------------------------------------------------------
#ifndef STATUS_OK
#define STATUS_OK 0
#endif

#ifndef STATUS_ERROR
#define STATUS_ERROR -1
#endif

//: ----------------------------------------------------------------------------
//: ANSI Color Code Strings
//:
//: Taken from:
//: http://pueblo.sourceforge.net/doc/manual/ansi_color_codes.html
//: ----------------------------------------------------------------------------
#define ANSI_COLOR_OFF          "\033[0m"
#define ANSI_COLOR_FG_BLACK     "\033[01;30m"
#define ANSI_COLOR_FG_RED       "\033[01;31m"
#define ANSI_COLOR_FG_GREEN     "\033[01;32m"
#define ANSI_COLOR_FG_YELLOW    "\033[01;33m"
#define ANSI_COLOR_FG_BLUE      "\033[01;34m"
#define ANSI_COLOR_FG_MAGENTA   "\033[01;35m"
#define ANSI_COLOR_FG_CYAN      "\033[01;36m"
#define ANSI_COLOR_FG_WHITE     "\033[01;37m"
#define ANSI_COLOR_FG_DEFAULT   "\033[01;39m"
#define ANSI_COLOR_BG_BLACK     "\033[01;40m"
#define ANSI_COLOR_BG_RED       "\033[01;41m"
#define ANSI_COLOR_BG_GREEN     "\033[01;42m"
#define ANSI_COLOR_BG_YELLOW    "\033[01;43m"
#define ANSI_COLOR_BG_BLUE      "\033[01;44m"
#define ANSI_COLOR_BG_MAGENTA   "\033[01;45m"
#define ANSI_COLOR_BG_CYAN      "\033[01;46m"
#define ANSI_COLOR_BG_WHITE     "\033[01;47m"
#define ANSI_COLOR_BG_DEFAULT   "\033[01;49m"


//: ----------------------------------------------------------------------------
//: Macros
//: ----------------------------------------------------------------------------
#ifndef _U_
#define _U_ __attribute__((unused))
#endif
#define UNUSED(x) ( (void)(x) )
#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))
#define NDBG_PRINT(...) \
        do { \
                fprintf(stdout, "%s:%s.%d: ", __FILE__, __FUNCTION__, __LINE__); \
                fprintf(stdout, __VA_ARGS__);               \
                fflush(stdout); \
        } while(0)

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_CS(NAME, VALUE)                                                \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),        \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

//: ----------------------------------------------------------------------------
//: Enums
//: ----------------------------------------------------------------------------
enum
{
        IO_NONE,
        WANT_READ,
        WANT_WRITE
};

//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------
struct Connection {
  SSL *l_ssl;
  nghttp2_session *session;
  /* WANT_READ if SSL/TLS connection needs more input; or WANT_WRITE
     if it needs more output; or IO_NONE. This is necessary because
     SSL/TLS re-negotiation is possible at any time. nghttp2 API
     offers similar functions like nghttp2_session_want_read() and
     nghttp2_session_want_write() but they do not take into account
     SSL/TSL connection. */
  int want_io;
};

typedef struct _request {
        std::string m_host;
        std::string m_path;
        uint16_t m_port;
        int32_t m_stream_id;
} request_t;

//: ----------------------------------------------------------------------------
//: \details: TODOPrints error message |msg| and exit.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
//NGHTTP2_NORETURN
static void die(const char *msg)
{
        fprintf(stderr, "FATAL: %s\n", msg);
        exit(EXIT_FAILURE);
}

//: ----------------------------------------------------------------------------
//: \details: Prints error containing the function name |func| and message |msg|
//:           and exit.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
//NGHTTP2_NORETURN
static void dief(const char *func, const char *msg)
{
        fprintf(stderr, "FATAL: %s: %s\n", func, msg);
        exit(EXIT_FAILURE);
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
/*
 * Prints error containing the function name |func| and error code
 * |error_code| and exit.
 */
//NGHTTP2_NORETURN
static void diec(const char *func, int error_code)
{
        fprintf(stderr, "FATAL: %s: error_code=%d, msg=%s\n", func, error_code, nghttp2_strerror(error_code));
        exit(EXIT_FAILURE);
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *session _U_, const uint8_t *data, size_t length, int flags _U_,
                void *user_data)
{
        struct Connection *connection;
        int rv;
        connection = (struct Connection *) user_data;
        connection->want_io = IO_NONE;
        ERR_clear_error();
        rv = SSL_write(connection->l_ssl, data, (int) length);
        if (rv <= 0)
        {
                int err = SSL_get_error(connection->l_ssl, rv);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                {
                        connection->want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
                        rv = NGHTTP2_ERR_WOULDBLOCK;
                } else
                {
                        rv = NGHTTP2_ERR_CALLBACK_FAILURE;
                }
        }
        return rv;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
static ssize_t recv_callback(nghttp2_session *session _U_, uint8_t *buf, size_t length, int flags _U_, void *user_data)
{
        struct Connection *connection;
        int rv;
        connection = (struct Connection *) user_data;
        connection->want_io = IO_NONE;
        ERR_clear_error();
        rv = SSL_read(connection->l_ssl, buf, (int) length);
        if (rv < 0)
        {
                int err = SSL_get_error(connection->l_ssl, rv);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                {
                        connection->want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
                        rv = NGHTTP2_ERR_WOULDBLOCK;
                } else
                {
                        rv = NGHTTP2_ERR_CALLBACK_FAILURE;
                }
        } else if (rv == 0)
        {
                rv = NGHTTP2_ERR_EOF;
        }
        return rv;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data _U_)
{
        size_t i;
        switch (frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id))
                {
                        const nghttp2_nv *nva = frame->headers.nva;
                        printf("[INFO] C ----------------------------> S (HEADERS)\n");
                        for (i = 0; i < frame->headers.nvlen; ++i)
                        {
                                fwrite(nva[i].name, 1, nva[i].namelen, stdout);
                                printf(": ");
                                fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
                                printf("\n");
                        }
                }
                break;
        case NGHTTP2_RST_STREAM:
                printf("[INFO] C ----------------------------> S (RST_STREAM)\n");
                break;
        case NGHTTP2_GOAWAY:
                printf("[INFO] C ----------------------------> S (GOAWAY)\n");
                break;
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data _U_)
{
        size_t i;
        switch (frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
                {
                        const nghttp2_nv *nva = frame->headers.nva;
                        request_t *l_req;
                        l_req = (request_t *) nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
                        if (l_req)
                        {
                                printf("[INFO] C <---------------------------- S (HEADERS)\n");
                                for (i = 0; i < frame->headers.nvlen; ++i)
                                {
                                        fwrite(nva[i].name, 1, nva[i].namelen, stdout);
                                        printf(": ");
                                        fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
                                        printf("\n");
                                }
                        }
                }
                break;
        case NGHTTP2_RST_STREAM:
                printf("[INFO] C <---------------------------- S (RST_STREAM)\n");
                break;
        case NGHTTP2_GOAWAY:
                printf("[INFO] C <---------------------------- S (GOAWAY)\n");
                break;
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code _U_,
                void *user_data _U_)
{

        request_t *l_req;
        l_req = (request_t *) nghttp2_session_get_stream_user_data(session, stream_id);
        if (l_req)
        {
                int rv;
                rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

                if (rv != 0)
                {
                        diec("nghttp2_session_terminate_session", rv);
                }
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags _U_, int32_t stream_id,
                const uint8_t *data, size_t len, void *user_data _U_)
{
        request_t *l_req;
        l_req = (request_t *)nghttp2_session_get_stream_user_data(session, stream_id);
        if (l_req) {
                printf("[INFO] C <---------------------------- S (DATA chunk)\n"
                                "%lu bytes\n", (unsigned long int) len);
                fwrite(data, 1, len, stdout);
                printf("\n");
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
/*
 * Callback function for TLS NPN. Since this program only supports
 * HTTP/2 protocol, if server does not offer HTTP/2 the nghttp2
 * library supports, we terminate program.
 */
static int select_next_proto_cb(SSL *l_ssl _U_, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg _U_) {
        int rv;
        /* nghttp2_select_next_protocol() selects HTTP/2 protocol the
         nghttp2 library supports. */
        rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
        if (rv <= 0)
        {
                die("Server did not advertise HTTP/2 protocol");
        }
        return SSL_TLSEXT_ERR_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void print_header(FILE *f,
                         const uint8_t *name,
                         size_t namelen,
                         const uint8_t *value,
                         size_t valuelen)
{
        fprintf(f, "%s", ANSI_COLOR_FG_BLUE);
        fwrite(name, namelen, 1, f);
        fprintf(f, "%s", ANSI_COLOR_OFF);
        fprintf(f, ": ");
        fprintf(f, "%s", ANSI_COLOR_FG_GREEN);
        fwrite(value, valuelen, 1, f);
        fprintf(f, "%s", ANSI_COLOR_OFF);
        fprintf(f, "\n");
}

//: ----------------------------------------------------------------------------
//: \details: Print HTTP headers to |f|. Please note that this function does not
//:           take into account that header name and value are sequence of
//:           octets, therefore they may contain non-printable characters.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void print_headers(FILE *f, const nghttp2_nv *nva, size_t nvlen)
{
        size_t i;
        for (i = 0; i < nvlen; ++i)
        {
                print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
        }
        fprintf(f, "\n");
}

//: ----------------------------------------------------------------------------
//: \details: Print the version.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "h2_client http2 client example (using nghttp2 lib).\n");
        fprintf(a_stream, "               Version: %s\n", "0.0.0");
        exit(a_exit_code);
}

//: ----------------------------------------------------------------------------
//: \details: Print the command line help.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: h2_client [https://]hostname[:port]/path [options]\n");
        fprintf(a_stream, "Options are:\n");
        fprintf(a_stream, "  -h, --help           Display this help and exit.\n");
        fprintf(a_stream, "  -V, --version        Display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        exit(a_exit_code);
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int main(int argc, char **argv)
{
        // -------------------------------------------
        // Get args...
        // -------------------------------------------
        char l_opt;
        std::string l_arg;
        int l_option_index = 0;
        bool l_input_flag = false;
        struct option l_long_options[] =
                {
                { "help",           0, 0, 'h' },
                { "version",        0, 0, 'V' },

                // list sentinel
                { 0, 0, 0, 0 }
        };

        // -------------------------------------------
        // Assume unspecified arg url...
        // TODO Unsure if good way to allow unspecified
        // arg...
        // -------------------------------------------
        std::string l_url;
        bool is_opt = false;
        for(int i_arg = 1; i_arg < argc; ++i_arg) {
                if(argv[i_arg][0] == '-') {
                        is_opt = true;
                }
                else if(argv[i_arg][0] != '-' && is_opt == false) {
                        l_url = std::string(argv[i_arg]);
                        l_input_flag = true;
                        break;
                } else {
                        is_opt = false;
                }
        }

        // -------------------------------------------------
        // Args...
        // -------------------------------------------------
        char l_short_arg_list[] = "hV";
        while ((l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_options, &l_option_index)) != -1)
        {

                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                //printf("arg[%c=%d]: %s\n", l_opt, l_option_index, l_arg.c_str());
                switch (l_opt)
                {
                // ---------------------------------------
                // Help
                // ---------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // ---------------------------------------
                // Version
                // ---------------------------------------
                case 'V':
                {
                        print_version(stdout, 0);
                        break;
                }
                // What???
                case '?':
                {
                        // Required argument was missing
                        // '?' is provided when the 3rd arg to getopt_long does not begin with a ':', and is preceeded
                        // by an automatic error message.
                        printf("  Exiting.\n");
                        print_usage(stdout, -1);
                        break;
                }
                // Huh???
                default:
                {
                        printf("Unrecognized option.\n");
                        print_usage(stdout, -1);
                        break;
                }
                }
        }

        // Verify input
        if(!l_input_flag)
        {
                printf("Error: url required.");
                print_usage(stdout, -1);
        }

        if(l_url.empty())
        {
                die("Specify a https URI");
        }
        int rv;

        // -------------------------------------------------
        // Signals...
        // -------------------------------------------------
        struct sigaction act;
        memset(&act, 0, sizeof(struct sigaction));
        act.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &act, 0);

        // -------------------------------------------------
        // tls setup...
        // -------------------------------------------------
        tls_init();
        SSL_CTX *l_ctx;
        l_ctx = tls_create_ctx();
        if(!l_ctx)
        {
                return STATUS_ERROR;
        }
        SSL_CTX_set_next_proto_select_cb(l_ctx, select_next_proto_cb, NULL);

        // -------------------------------------------------
        // parse url
        // -------------------------------------------------
        std::string l_host;
        uint16_t l_port;
        std::string l_path;
        parse_url(l_url, l_host, l_port, l_path);
        if(l_path.empty()) l_path = "/";

        request_t l_req;
        l_req.m_host = l_host;
        l_req.m_port = l_port;
        l_req.m_path = l_path;
        l_req.m_stream_id = -1;

        // -------------------------------------------------
        // Connect
        // -------------------------------------------------
        SSL *l_tls;
        l_tls = tls_connect(l_ctx, l_host, l_port);
        if(!l_tls)
        {
                return STATUS_ERROR;
        }
        int l_fd;
        l_fd = SSL_get_fd(l_tls);

        // -------------------------------------------------
        // make non-blocking
        // -------------------------------------------------
        int l_flags;
        int l_s;
        while ((l_flags = fcntl(l_fd, F_GETFL, 0)) == -1 && errno == EINTR);
        if (l_flags == -1)
        {
                printf("Error performing fcntl. Reason: %s\n", strerror(errno));
                // TODO Reason...
                if(l_tls) {SSL_free(l_tls); l_tls = NULL;}
                return STATUS_ERROR;
        }
        while ((l_s = fcntl(l_fd, F_SETFL, l_flags | O_NONBLOCK)) == -1 && errno == EINTR);
        if (l_s == -1)
        {
                printf("Error performing fcntl. Reason: %s\n", strerror(errno));
                // TODO Reason...
                if(l_tls) {SSL_free(l_tls); l_tls = NULL;}
                return STATUS_ERROR;
        }

        // -------------------------------------------------
        // no-delay
        // -------------------------------------------------
        int l_set = 1;
        l_s = setsockopt(l_fd, IPPROTO_TCP, TCP_NODELAY, &l_set, (socklen_t) sizeof(l_set));
        if (l_s == -1)
        {
                printf("Error performing setsockopt. Reason: %s\n", strerror(errno));
                // TODO Reason...
                if(l_tls) {SSL_free(l_tls); l_tls = NULL;}
                return STATUS_ERROR;
        }

        printf("[INFO] SSL/TLS handshake completed\n");


        // -------------------------------------------------
        // Client setup
        // -------------------------------------------------
        // Setup callback functions. nghttp2 API offers many
        // callback functions, but most of them are optional.
        // The send_callback is always required. Since we use
        // nghttp2_session_recv(), the recv_callback is also
        // required.
        // -------------------------------------------------
        nghttp2_session_callbacks *callbacks;
        rv = nghttp2_session_callbacks_new(&callbacks);
        if (rv != 0)
        {
                diec("nghttp2_session_callbacks_new", rv);
        }
        nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
        nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
        nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
        struct Connection connection;
        connection.l_ssl = l_tls;
        connection.want_io = IO_NONE;
        rv = nghttp2_session_client_new(&connection.session, callbacks, &connection);

        nghttp2_session_callbacks_del(callbacks);

        if (rv != 0)
        {
                diec("nghttp2_session_client_new", rv);
        }

        rv = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_NONE, NULL, 0);

        if (rv != 0)
        {
                diec("nghttp2_submit_settings", rv);
        }

        // -------------------------------------------------
        // Submit the HTTP request to the outbound queue.
        // -------------------------------------------------
        // Submits the request |req| to the connection |connection|.  This
        // function does not send packets; just append the request to the
        // internal queue in |connection->session|.
        // -------------------------------------------------
        int32_t stream_id;
        // Make sure that the last item is NULL
        const nghttp2_nv l_hdrs[] = {
                MAKE_NV(   ":method",    "GET"),
                MAKE_NV_CS(":path",      l_req.m_path.c_str()),
                MAKE_NV(   ":scheme",    "https"),
                MAKE_NV_CS(":authority", l_req.m_host.c_str()),
                MAKE_NV(   "accept",     "*/*"),
                MAKE_NV(   "user-agent", "nghttp2/" NGHTTP2_VERSION)
        };
        print_headers(stdout, l_hdrs, ARRLEN(l_hdrs));
        stream_id = nghttp2_submit_request(connection.session,
                                           NULL,
                                           l_hdrs,
                                           ARRLEN(l_hdrs),
                                           NULL,
                                           &l_req);
        if (stream_id < 0)
        {
                diec("nghttp2_submit_request", stream_id);
        }
        l_req.m_stream_id = stream_id;
        printf("[INFO] Stream ID = %d\n", stream_id);


        // -------------------------------------------------
        // Poll for response
        // -------------------------------------------------
        nfds_t npollfds = 1;
        struct pollfd pollfds[1];
        pollfds[0].fd = l_fd;

        // Update |pollfd| based on the state of |connection|.
        pollfds->events = 0;
        if(nghttp2_session_want_read(connection.session)  || connection.want_io == WANT_READ)  { pollfds->events |= POLLIN;}
        if(nghttp2_session_want_write(connection.session) || connection.want_io == WANT_WRITE) { pollfds->events |= POLLOUT;}

        /* Event loop */
        while (nghttp2_session_want_read(connection.session) || nghttp2_session_want_write(connection.session))
        {
                int nfds = poll(pollfds, npollfds, -1);
                if (nfds == -1)
                {
                        dief("poll", strerror(errno));
                }
                // Performs the network I/O.
                if (pollfds[0].revents & (POLLIN | POLLOUT))
                {
                        rv = nghttp2_session_recv(connection.session);
                        if (rv != 0)
                        {
                                diec("nghttp2_session_recv", rv);
                        }
                        rv = nghttp2_session_send(connection.session);
                        if (rv != 0)
                        {
                                diec("nghttp2_session_send", rv);
                        }
                }
                if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR))
                {
                        die("Connection error");
                }

                // Update |pollfd| based on the state of |connection|.
                pollfds->events = 0;
                if(nghttp2_session_want_read(connection.session)  || connection.want_io == WANT_READ)  { pollfds->events |= POLLIN;}
                if(nghttp2_session_want_write(connection.session) || connection.want_io == WANT_WRITE) { pollfds->events |= POLLOUT;}

        }

        /* Resource cleanup */
        nghttp2_session_del(connection.session);
        SSL_shutdown(l_tls);
        SSL_free(l_tls);
        SSL_CTX_free(l_ctx);
        shutdown(l_fd, SHUT_WR);
        close(l_fd);
        return STATUS_OK;
}
