//: ----------------------------------------------------------------------------
//: \file:    h2_client.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    10/26/2016
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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <getopt.h> // For getopt_long
#include "nghttp2/nghttp2.h"
#include "support.h"

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
//: Macros
//: ----------------------------------------------------------------------------
#ifndef _U_
#define _U_ __attribute__((unused))
#endif
#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

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
enum {
        IO_NONE,
        WANT_READ,
        WANT_WRITE
};

//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------
typedef struct _connection {
        SSL *m_tls;
        nghttp2_session *m_session;
        // -----------------------------------------------------------
        // WANT_READ if SSL/TLS l_conn needs more input; or WANT_WRITE
        // if it needs more output; or IO_NONE. This is necessary because
        // SSL/TLS re-negotiation is possible at any time. nghttp2 API
        // offers similar functions like nghttp2_session_want_read() and
        // nghttp2_session_want_write() but they do not take into account
        // SSL/TSL l_conn.m_
        // -----------------------------------------------------------
        int m_want_io;
} connection_t;

typedef struct _request {
        std::string m_host;
        std::string m_path;
        uint16_t m_port;
        int32_t m_stream_id;
} request_t;

//: ----------------------------------------------------------------------------
//: \details: The implementation of nghttp2_send_callback type. Here we write
//:           |data| with size |length| to the network and return the number of
//:           bytes actually written. See the documentation of
//:           nghttp2_send_callback for the details.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static ssize_t send_callback(nghttp2_session *a_session _U_,
                             const uint8_t *data,
                             size_t length,
                             int a_flags _U_,
                             void *user_data)
{
        connection_t *l_conn;
        int l_s;
        l_conn = (connection_t *)user_data;
        l_conn->m_want_io = IO_NONE;
        ERR_clear_error();
        l_s = SSL_write(l_conn->m_tls, data, (int)length);
        if (l_s <= 0)
        {
                int err = SSL_get_error(l_conn->m_tls, l_s);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                {
                        l_conn->m_want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
                        l_s = NGHTTP2_ERR_WOULDBLOCK;
                } else
                {
                        l_s = NGHTTP2_ERR_CALLBACK_FAILURE;
                }
        }
        return l_s;
}

//: ----------------------------------------------------------------------------
//: \details: The implementation of nghttp2_recv_callback type. Here we read data
//:           from the network and write them in |buf|. The capacity of |buf| is
//:           |length| bytes. Returns the number of bytes stored in |buf|. See
//:           the documentation of nghttp2_recv_callback for the details.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static ssize_t recv_callback(nghttp2_session *a_session _U_, uint8_t *buf, size_t length, int a_flags _U_, void *user_data)
{
        connection_t *l_conn;
        int l_s;
        l_conn = (connection_t *) user_data;
        l_conn->m_want_io = IO_NONE;
        ERR_clear_error();
        l_s = SSL_read(l_conn->m_tls, buf, (int) length);
        if (l_s < 0)
        {
                int err = SSL_get_error(l_conn->m_tls, l_s);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                {
                        l_conn->m_want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
                        l_s = NGHTTP2_ERR_WOULDBLOCK;
                } else
                {
                        l_s = NGHTTP2_ERR_CALLBACK_FAILURE;
                }
        } else if (l_s == 0)
        {
                l_s = NGHTTP2_ERR_EOF;
        }
        return l_s;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int on_frame_send_callback(nghttp2_session *a_session, const nghttp2_frame *frame, void *user_data _U_)
{
        size_t i;
        switch (frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if (nghttp2_session_get_stream_user_data(a_session, frame->hd.stream_id))
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
static int on_frame_recv_callback(nghttp2_session *a_session, const nghttp2_frame *frame, void *user_data _U_)
{
        size_t i;
        switch (frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
                {
                        const nghttp2_nv *nva = frame->headers.nva;
                        request_t *l_req;
                        l_req = (request_t *) nghttp2_session_get_stream_user_data(a_session, frame->hd.stream_id);
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
//: \details: The implementation of nghttp2_on_stream_close_callback type. We use
//:           this function to know the response is fully received. Since we just
//:           fetch 1 resource in this program, after reception of the response,
//:           we submit GOAWAY and close the a_session.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int on_stream_close_callback(nghttp2_session *a_session,
                int32_t stream_id, uint32_t error_code _U_,
                void *user_data _U_)
{
        request_t *l_req;
        l_req = (request_t *) nghttp2_session_get_stream_user_data(a_session, stream_id);
        if (l_req)
        {
                int l_s;
                l_s = nghttp2_session_terminate_session(a_session, NGHTTP2_NO_ERROR);

                if (l_s != 0)
                {
                        fprintf(stderr, "Error %s: error_code=%d, msg=%s\n", "nghttp2_session_terminate_session", error_code, nghttp2_strerror(error_code));
                        exit(-1);
                }
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: The implementation of nghttp2_on_data_chunk_recv_callback type. We
//:           use this function to print the received response body.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int on_data_chunk_recv_callback(nghttp2_session *a_session, uint8_t a_flags _U_, int32_t stream_id,
                const uint8_t *data, size_t len, void *user_data _U_)
{
        request_t *l_req;
        l_req = (request_t *) nghttp2_session_get_stream_user_data(a_session, stream_id);
        if (l_req)
        {
                printf("[INFO] C <---------------------------- S (DATA chunk)\n"
                                "%lu bytes\n", (unsigned long int) len);
                fwrite(data, 1, len, stdout);
                printf("\n");
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: Callback function for TLS NPN. Since this program only supports
//:           HTTP/2 protocol, if server does not offer HTTP/2 the nghttp2
//:           library supports, we terminate program.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int select_next_proto_cb(SSL *ssl _U_,
                                unsigned char **out,
                                unsigned char *outlen,
                                const unsigned char *in,
                                unsigned int inlen,
                                void *arg _U_)
{
        int l_s;
        /* nghttp2_select_next_protocol() selects HTTP/2 protocol the
         nghttp2 library supports. */
        l_s = nghttp2_select_next_protocol(out, outlen, in, inlen);
        if (l_s <= 0)
        {
                printf("Error Server did not advertise HTTP/2 protocol\n");
                exit(-1);
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
        fprintf(a_stream, "h2_client http2 client example (using nghttp2 library).\n");
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

        // -------------------------------------------------
        // signals
        // -------------------------------------------------
        struct sigaction act;
        memset(&act, 0, sizeof(struct sigaction));
        act.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &act, 0);

        // -------------------------------------------------
        // lib setup
        // -------------------------------------------------
        tls_init();

        // -------------------------------------------------
        // create request
        // -------------------------------------------------
        // Get host/path
        std::string l_host;
        std::string l_path;
        uint16_t l_port = 443;
        int32_t l_s;
        l_s = parse_url(l_url, l_host, l_port, l_path);
        if(l_s != 0)
        {
                printf("Error performing parse_url.\n");
                return STATUS_ERROR;
        }
        request_t l_req;
        l_req.m_host = l_host;
        l_req.m_port = l_port;
        l_req.m_path = l_path;

        // -------------------------------------------------
        // tls ctx
        // -------------------------------------------------
        SSL_CTX *l_ctx;
        l_ctx = tls_create_ctx();
        // TODO check status
        // Set NPN callback
        SSL_CTX_set_next_proto_select_cb(l_ctx, select_next_proto_cb, NULL);

        // -------------------------------------------------
        // connect
        // -------------------------------------------------
        SSL *l_tls;
        l_tls = tls_connect(l_ctx, l_req.m_host, l_req.m_port, true);
        if(!l_tls)
        {
                printf("Error performing tls_connect\n");
                return STATUS_ERROR;
        }
        connection_t l_conn;
        l_conn.m_tls = l_tls;
        l_conn.m_want_io = IO_NONE;
        int l_fd = SSL_get_fd(l_tls);

        printf("[INFO] SSL/TLS handshake completed\n");
        // -------------------------------------------------
        // setup callbacks
        // -------------------------------------------------
        nghttp2_session_callbacks *callbacks;
        l_s = nghttp2_session_callbacks_new(&callbacks);
        if (l_s != 0)
        {
                printf("Error %s: error_code=%d, msg=%s\n", "nghttp2_session_callbacks_new", l_s, nghttp2_strerror(l_s));
                return STATUS_ERROR;
        }
        nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
        nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
        nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);

        // -------------------------------------------------
        // client setup
        // -------------------------------------------------
        l_s = nghttp2_session_client_new(&l_conn.m_session, callbacks, &l_conn);
        nghttp2_session_callbacks_del(callbacks);
        if (l_s != 0)
        {
                printf("Error %s: error_code=%d, msg=%s\n", "nghttp2_session_client_new", l_s, nghttp2_strerror(l_s));
                return STATUS_ERROR;
        }

        // -------------------------------------------------
        // submit settings
        // -------------------------------------------------
        l_s = nghttp2_submit_settings(l_conn.m_session, NGHTTP2_FLAG_NONE, NULL, 0);
        if (l_s != 0)
        {
                printf("Error %s: error_code=%d, msg=%s\n", "nghttp2_submit_settings", l_s, nghttp2_strerror(l_s));
                return STATUS_ERROR;
        }

        // -------------------------------------------------
        // Submit the HTTP request to the outbound queue.
        // -------------------------------------------------
        // Submits the request |req| to the l_conn |l_conn|.
        // This function does not send packets; just append
        // the request to the internal queue in
        // |a_conn->m_session|.
        // Make sure that the last item is NULL
        // -------------------------------------------------
        char l_port_str[16];
        snprintf(l_port_str, 16, "%u", l_req.m_port);
        const nghttp2_nv l_hdrs[] =
        {
                MAKE_NV(   ":method",    "GET"),
                MAKE_NV_CS(":path",      l_req.m_path.c_str()),
                MAKE_NV(   ":scheme",    "l_req"),
                MAKE_NV_CS(":authority", l_port_str),
                MAKE_NV(   "accept",     "*/*"),
                MAKE_NV(   "user-agent", "nghttp2/" NGHTTP2_VERSION)
        };

        int32_t l_val;
        print_headers(stdout, l_hdrs, ARRLEN(l_hdrs));
        printf("PRINT HEADERS\n");
        l_val = nghttp2_submit_request(l_conn.m_session, NULL, l_hdrs, sizeof(l_hdrs) / sizeof(l_hdrs[0]), NULL, &l_conn);
        if (l_val < 0)
        {
                printf("Error %s: error_code=%d, msg=%s\n", "nghttp2_submit_request", l_s, nghttp2_strerror(l_s));
                return STATUS_ERROR;
        }
        l_req.m_stream_id = l_val;
        printf("[INFO] Stream ID = %d\n", l_req.m_stream_id);

        // -------------------------------------------------
        // Poll for response
        // -------------------------------------------------
        nfds_t npollfds = 1;
        struct pollfd pollfds[1];
        pollfds[0].fd = l_fd;

        // ---------------------------------------
        // poll
        // ---------------------------------------
        pollfds->events = 0;
        if (nghttp2_session_want_read(l_conn.m_session) || l_conn.m_want_io == WANT_READ) {
                pollfds->events |= POLLIN;
        }
        if (nghttp2_session_want_write(l_conn.m_session) || l_conn.m_want_io == WANT_WRITE) {
                pollfds->events |= POLLOUT;
        }

        while (nghttp2_session_want_read(l_conn.m_session) ||
               nghttp2_session_want_write(l_conn.m_session))
        {
                int nfds = poll(pollfds, npollfds, -1);
                if (nfds == -1)
                {
                        printf("Error poll. Reason: %s\n", strerror(errno));
                        return STATUS_ERROR;
                }
                if (pollfds[0].revents & (POLLIN | POLLOUT))
                {
                        int l_s;
                        l_s = nghttp2_session_recv(l_conn.m_session);
                        if (l_s != 0)
                        {
                                printf("Error %s: error_code=%d, msg=%s\n", "nghttp2_session_recv", l_s, nghttp2_strerror(l_s));
                                return STATUS_ERROR;
                        }
                        l_s = nghttp2_session_send(l_conn.m_session);
                        if (l_s != 0)
                        {
                                printf("Error %s: error_code=%d, msg=%s\n", "nghttp2_session_send", l_s, nghttp2_strerror(l_s));
                                return STATUS_ERROR;

                        }
                }
                if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR))
                {
                        printf("Connection error\n");
                        return STATUS_ERROR;
                }

                // ---------------------------------------
                // poll
                // ---------------------------------------
                pollfds->events = 0;
                if (nghttp2_session_want_read(l_conn.m_session) || l_conn.m_want_io == WANT_READ) {
                        pollfds->events |= POLLIN;
                }
                if (nghttp2_session_want_write(l_conn.m_session) || l_conn.m_want_io == WANT_WRITE) {
                        pollfds->events |= POLLOUT;
                }

        }

        // -------------------------------------------------
        // Cleanup
        // -------------------------------------------------
        nghttp2_session_del(l_conn.m_session);
        SSL_shutdown(l_tls);
        SSL_free(l_tls);
        SSL_CTX_free(l_ctx);
        shutdown(l_fd, SHUT_WR);
        close(l_fd);

        return 0;
}
