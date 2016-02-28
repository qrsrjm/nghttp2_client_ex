//: ----------------------------------------------------------------------------
//: \file:    nghttp2_client_ex.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    02/20/2016
//: ----------------------------------------------------------------------------

//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h> // For getopt_long
#include <stdint.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <string>
#include <openssl/ssl.h>

// For errx
#include <err.h>

// For sleep
#include <unistd.h>

#include "support.h"
#include "nghttp2/nghttp2.h"

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

//: ----------------------------------------------------------------------------
//: nghttp2 support routines
//: ----------------------------------------------------------------------------

//: ----------------------------------------------------------------------------
//: \details: NPN TLS extension client callback. We check that server advertised
//:           the HTTP/2 protocol the nghttp2 library supports. If not, exit
//:           the program.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int select_next_proto_cb(SSL *a_ssl _U_,
                                unsigned char **a_out,
                                unsigned char *a_outlen,
                                const unsigned char *a_in,
                                unsigned int a_inlen,
                                void *a_arg _U_)
{
        if (nghttp2_select_next_protocol(a_out, a_outlen, a_in, a_inlen) <= 0)
        {
                errx(1, "Server did not advertise " NGHTTP2_PROTO_VERSION_ID);
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
        fwrite(name, namelen, 1, f);
        fprintf(f, ": ");
        fwrite(value, valuelen, 1, f);
        fprintf(f, "\n");
}

//: ----------------------------------------------------------------------------
//: \details: Print HTTP headers to |f|. Please note that this function does not
//:           take into account that header name and value are sequence of
//:           octets, therefore they may contain non-printable characters.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen)
{
        size_t i;
        for (i = 0; i < nvlen; ++i)
        {
                print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
        }
        fprintf(f, "\n");
}

//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------
typedef struct
{
        int32_t m_id;              // The stream ID of this stream
        bool m_closed;
} ngxxx_stream;

typedef struct
{
        SSL *m_tls;
        nghttp2_session *m_session;
        ngxxx_stream *m_stream;
} ngxxx_session;

//: ----------------------------------------------------------------------------
//: \details: nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
//:           to the network. Because we are using libevent bufferevent, we just
//:           write those bytes into bufferevent buffer
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static ssize_t ngxxx_send_cb(nghttp2_session *a_session _U_,
                             const uint8_t *a_data,
                             size_t a_length,
                             int a_flags _U_,
                             void *a_user_data)
{
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        UNUSED(l_session);
        //NDBG_PRINT("SEND_CB\n");
        //mem_display(a_data, a_length);
        int l_s;
        l_s = SSL_write(l_session->m_tls, a_data, a_length);
        //NDBG_PRINT("%sWRITE%s: l_s: %d\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF, l_s);
        if((l_s < 0) ||
           ((size_t)l_s < a_length))
        {
                NDBG_PRINT("Error performing SSL_write: l_s: %d\n", l_s);
                return -1;
        }
        return (ssize_t)l_s;
}

//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_frame_recv_callback: Called when nghttp2 library
//:           received a complete frame from the remote peer.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_frame_recv_cb(nghttp2_session *a_session,
                               const nghttp2_frame *a_frame,
                               void *a_user_data)
{
        //NDBG_PRINT("%sFRAME%s: TYPE[%6u]\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF, a_frame->hd.type);
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        switch (a_frame->hd.type)
        {
        case NGHTTP2_HEADERS:
        {
                if ((a_frame->headers.cat == NGHTTP2_HCAT_RESPONSE) &&
                    (l_session->m_stream->m_id == a_frame->hd.stream_id))
                {
                        //fprintf(stderr, "All headers received\n");
                }
                break;
        }
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
//:           received from the remote peer. In this implementation, if the frame
//:           is meant to the stream we initiated, print the received data in
//:           stdout, so that the user can redirect its output to the file
//:           easily.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_data_chunk_recv_cb(nghttp2_session *a_session _U_,
                                    uint8_t a_flags _U_,
                                    int32_t a_stream_id,
                                    const uint8_t *a_data,
                                    size_t a_len,
                                    void *a_user_data)
{
        //NDBG_PRINT("%sCHUNK%s: \n", ANSI_COLOR_BG_BLUE, ANSI_COLOR_OFF);
        ngxxx_session *l_session = (ngxxx_session *) a_user_data;
        if (l_session->m_stream->m_id == a_stream_id)
        {
                fwrite(a_data, a_len, 1, stdout);
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_stream_close_callback: Called when a stream is about to
//:           closed. This example program only deals with 1 HTTP request (1
//:           stream), if it is closed, we send GOAWAY and tear down the
//:           session
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_stream_close_cb(nghttp2_session *a_session,
                                 int32_t a_stream_id,
                                 uint32_t a_error_code,
                                 void *a_user_data)
{
        //NDBG_PRINT("%sCLOSE%s: \n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
        ngxxx_session *l_session = (ngxxx_session *) a_user_data;
        int l_rv;
        l_session->m_stream->m_closed = true;
        if (l_session->m_stream->m_id == a_stream_id)
        {
                //fprintf(stderr, "Stream %d closed with error_code=%d\n", a_stream_id, a_error_code);
                l_rv = nghttp2_session_terminate_session(a_session, NGHTTP2_NO_ERROR);
                if (l_rv != 0)
                {
                        return NGHTTP2_ERR_CALLBACK_FAILURE;
                }
        }
        return 0;
}


//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_header_callback: Called when nghttp2 library emits
//:           single header name/value pair
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_header_cb(nghttp2_session *a_session _U_,
                           const nghttp2_frame *a_frame,
                           const uint8_t *a_name,
                           size_t a_namelen,
                           const uint8_t *a_value,
                           size_t a_valuelen,
                           uint8_t a_flags _U_,
                           void *a_user_data)
{
        //NDBG_PRINT("%sHEADER%s: \n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF);
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        switch (a_frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if ((a_frame->headers.cat == NGHTTP2_HCAT_RESPONSE) &&
                    (l_session->m_stream->m_id == a_frame->hd.stream_id))
                {
                        // Print response headers for the initiated request.
                        print_header(stdout, a_name, a_namelen, a_value, a_valuelen);
                        break;
                }
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: nghttp2_on_begin_headers_callback:
//:           Called when nghttp2 library gets started to receive header block.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int ngxxx_begin_headers_cb(nghttp2_session *a_session _U_,
                                  const nghttp2_frame *a_frame,
                                  void *a_user_data)
{
        //NDBG_PRINT("%sBEGIN_HEADERS%s: \n", ANSI_COLOR_BG_WHITE, ANSI_COLOR_OFF);
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        switch (a_frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if ((a_frame->headers.cat == NGHTTP2_HCAT_RESPONSE) &&
                     (l_session->m_stream->m_id == a_frame->hd.stream_id))
                {
                        //fprintf(stderr, "Response headers for stream ID=%d:\n", a_frame->hd.stream_id);
                }
                break;
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void ngxxx_init_nghttp2_session(ngxxx_session *a_session)
{
        nghttp2_session_callbacks *l_cb;
        nghttp2_session_callbacks_new(&l_cb);
        nghttp2_session_callbacks_set_send_callback(l_cb, ngxxx_send_cb);
        nghttp2_session_callbacks_set_on_frame_recv_callback(l_cb, ngxxx_frame_recv_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(l_cb, ngxxx_data_chunk_recv_cb);
        nghttp2_session_callbacks_set_on_stream_close_callback(l_cb, ngxxx_stream_close_cb);
        nghttp2_session_callbacks_set_on_header_callback(l_cb, ngxxx_header_cb);
        nghttp2_session_callbacks_set_on_begin_headers_callback(l_cb, ngxxx_begin_headers_cb);
        nghttp2_session_client_new(&(a_session->m_session), l_cb, a_session);
        nghttp2_session_callbacks_del(l_cb);
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void ngxxx_send_client_connection_header(ngxxx_session *a_session)
{
        nghttp2_settings_entry iv[1] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 } };
        int rv;

        /* client 24 bytes magic string will be sent by nghttp2 library */
        rv = nghttp2_submit_settings(a_session->m_session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
        if (rv != 0)
        {
                errx(1, "Could not submit SETTINGS: %s", nghttp2_strerror(rv));
        }
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#define MAKE_NV(NAME, VALUE, VALUELEN) {\
                (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,\
                NGHTTP2_NV_FLAG_NONE\
        }

#define MAKE_NV2(NAME, VALUE) {\
                (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,\
                NGHTTP2_NV_FLAG_NONE\
          }

//: ----------------------------------------------------------------------------
//: \details: Send HTTP request to the remote peer
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void ngxxx_submit_request(ngxxx_session *a_session,
                                 const std::string &a_schema,
                                 const std::string &a_host,
                                 const std::string &a_path)
{
        int32_t l_id;
        ngxxx_stream *l_stream = a_session->m_stream;
        nghttp2_nv l_hdrs[] =
        {
                MAKE_NV2(":method",   "GET"),
                MAKE_NV( ":scheme",    a_schema.c_str(), a_schema.length()),
                MAKE_NV( ":authority", a_host.c_str(), a_host.length()),
                MAKE_NV( ":path",      a_path.c_str(), a_path.length())
        };
        //fprintf(stderr, "Request headers:\n");
        print_headers(stdout, l_hdrs, ARRLEN(l_hdrs));
        l_id = nghttp2_submit_request(a_session->m_session, NULL, l_hdrs, ARRLEN(l_hdrs), NULL, l_stream);
        if (l_id < 0)
        {
                errx(1, "Could not submit HTTP request: %s", nghttp2_strerror(l_id));
        }
        l_stream->m_id = l_id;
}

//: ----------------------------------------------------------------------------
//: \details: Print the version.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "nghttp2 client example.\n");
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
        fprintf(a_stream, "Usage: nghttp2_client_ex [http[s]://]hostname[:port]/path [options]\n");
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
int main(int argc, char** argv)
{
        // -------------------------------------------
        // Get args...
        // -------------------------------------------
        char l_opt;
        std::string l_argument;
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
                        l_argument = std::string(optarg);
                }
                else
                {
                        l_argument.clear();
                }
                //printf("arg[%c=%d]: %s\n", l_opt, l_option_index, l_argument.c_str());
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

        // -------------------------------------------
        // Do stuff...
        // -------------------------------------------
        //printf("Connecting...\n");

        // Init tls...
        tls_init();

        // -------------------------------------------
        // TLS CTX
        // -------------------------------------------
        SSL_CTX *l_ctx = NULL;
        l_ctx = tls_create_ctx();
        if(!l_ctx)
        {
                printf("Error performing tls_create_ctx\n");
                return -1;
        }
        SSL_CTX_set_next_proto_select_cb(l_ctx, select_next_proto_cb, NULL);

        // Get host/path
        std::string l_host;
        std::string l_path;
        uint16_t l_port = 443;
        int32_t l_s;
        l_s = parse_url(l_url, l_host, l_port, l_path);
        if(l_s != 0)
        {
                printf("Error performing parse_url.\n");
        }

        // Connect
        SSL *l_tls = NULL;
        l_tls = tls_connect(l_ctx, l_host, l_port);
        if(!l_tls)
        {
                printf("Error performing ssl_connect\n");
                return -1;
        }

        // -------------------------------------------
        // Create session/stream
        // -------------------------------------------
        ngxxx_session *l_session = NULL;
        l_session = (ngxxx_session *)calloc(1, sizeof(ngxxx_session));
        l_session->m_stream = (ngxxx_stream *)calloc(1, sizeof(ngxxx_stream));
        l_session->m_stream->m_id = -1;
        l_session->m_stream->m_closed = false;
        l_session->m_tls = l_tls;

        // -------------------------------------------
        // Init session...
        // -------------------------------------------
        ngxxx_init_nghttp2_session(l_session);

        // -------------------------------------------
        // Send connection header
        // -------------------------------------------
        ngxxx_send_client_connection_header(l_session);

        // -------------------------------------------
        // Send Request
        // -------------------------------------------
        ngxxx_submit_request(l_session, "https", l_host, l_path);

        while(!l_session->m_stream->m_closed)
        {
                // -------------------------------------------
                // Session Send???
                // -------------------------------------------
                l_s = nghttp2_session_send(l_session->m_session);
                if (l_s != 0)
                {
                        warnx("Fatal error: %s", nghttp2_strerror(l_s));
                        // TODO
                        //delete_http2_session_data(session_data);
                        return -1;
                }
                //NDBG_PRINT("nghttp2_session_send: %d\n", l_s);

                // -------------------------------------------
                // Read Response...
                // -------------------------------------------
                char l_buf[16384];
                l_s = SSL_read(l_tls, l_buf, 16384);
                //NDBG_PRINT("%sREAD%s: l_s: %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_s);
                //if(l_s > 0) mem_display((uint8_t *)l_buf, l_s);
                ssize_t l_rl;
                l_rl = nghttp2_session_mem_recv(l_session->m_session, (const uint8_t *)l_buf, l_s);
                if(l_rl < 0)
                {
                        warnx("Fatal error: %s", nghttp2_strerror((int) l_rl));
                        // TODO
                        //delete_http2_session_data(session_data);
                        return -1;
                }
        }

        // -------------------------------------------
        // Cleanup...
        // -------------------------------------------
        SSL_shutdown(l_tls);
        SSL_CTX_free(l_ctx);
        //printf("Cleaning up...\n");
        return 0;
}
