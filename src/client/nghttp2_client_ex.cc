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

#include "support.h"
#include "nghttp2/nghttp2.h"

//: ----------------------------------------------------------------------------
//:
//: ----------------------------------------------------------------------------
#ifndef _U_
#define _U_ __attribute__((unused))
#endif

#define UNUSED(x) ( (void)(x) )

//: ----------------------------------------------------------------------------
//: nghttp2 support routines
//: ----------------------------------------------------------------------------

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
        const char *uri;           // The NULL-terminated URI string to retrieve.
        struct http_parser_url *u; // Parsed result of the |uri|

        char *authority;           // The authority portion of the |uri|, not NULL-terminated
        size_t authoritylen;       // The length of the |authority|

        char *path;                // The path portion of the |uri|, including query, not NULL-terminated
        size_t pathlen;            // The length of the |path|

        int32_t stream_id;         // The stream ID of this stream
} ngxxx_stream;

typedef struct
{
        nghttp2_session *session;
        ngxxx_stream *stream_data;
} ngxxx_session;

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
static ngxxx_stream *create_http2_stream_data(const char *uri, struct http_parser_url *u)
{
        /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
        size_t extra = 7;
        ngxxx_stream *stream_data = malloc(sizeof(ngxxx_stream));

        stream_data->uri = uri;
        stream_data->u = u;
        stream_data->stream_id = -1;

        stream_data->authoritylen = u->field_data[UF_HOST].len;
        stream_data->authority = malloc(stream_data->authoritylen + extra);
        memcpy(stream_data->authority, &uri[u->field_data[UF_HOST].off], u->field_data[UF_HOST].len);
        if (u->field_set & (1 << UF_PORT))
        {
                stream_data->authoritylen += (size_t) snprintf(stream_data->authority + u->field_data[UF_HOST].len,
                                extra, ":%u", u->port);
        }

        /* If we don't have path in URI, we use "/" as path. */
        stream_data->pathlen = 1;
        if (u->field_set & (1 << UF_PATH))
        {
                stream_data->pathlen = u->field_data[UF_PATH].len;
        }
        if (u->field_set & (1 << UF_QUERY))
        {
                /* +1 for '?' character */
                stream_data->pathlen += (size_t) (u->field_data[UF_QUERY].len + 1);
        }

        stream_data->path = malloc(stream_data->pathlen);
        if (u->field_set & (1 << UF_PATH))
        {
                memcpy(stream_data->path, &uri[u->field_data[UF_PATH].off], u->field_data[UF_PATH].len);
        } else
        {
                stream_data->path[0] = '/';
        }
        if (u->field_set & (1 << UF_QUERY))
        {
                stream_data->path[stream_data->pathlen - u->field_data[UF_QUERY].len - 1] = '?';
                memcpy(stream_data->path + stream_data->pathlen - u->field_data[UF_QUERY].len,
                                &uri[u->field_data[UF_QUERY].off], u->field_data[UF_QUERY].len);
        }

        return stream_data;
}
#endif

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
        // TODO
#if 0
        struct bufferevent *bev = session_data->bev;
        bufferevent_write(bev, data, length);
#endif
        return (ssize_t)a_length;
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
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        switch (a_frame->hd.type)
        {
        case NGHTTP2_HEADERS:
        {
                if ((a_frame->headers.cat == NGHTTP2_HCAT_RESPONSE) &&
                    (l_session->stream_data->stream_id == a_frame->hd.stream_id))
                {
                        fprintf(stderr, "All headers received\n");
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
        ngxxx_session *l_session = (ngxxx_session *) a_user_data;
        if (l_session->stream_data->stream_id == a_stream_id)
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
        ngxxx_session *l_session = (ngxxx_session *) a_user_data;
        int l_rv;
        if (l_session->stream_data->stream_id == a_stream_id)
        {
                fprintf(stderr, "Stream %d closed with error_code=%d\n", a_stream_id, a_error_code);
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
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        switch (a_frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if ((a_frame->headers.cat == NGHTTP2_HCAT_RESPONSE) &&
                    (l_session->stream_data->stream_id == a_frame->hd.stream_id))
                {
                        // Print response headers for the initiated request.
                        //print_header(stderr, name, namelen, value, valuelen);
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
        ngxxx_session *l_session = (ngxxx_session *)a_user_data;
        switch (a_frame->hd.type)
        {
        case NGHTTP2_HEADERS:
                if ((a_frame->headers.cat == NGHTTP2_HCAT_RESPONSE) &&
                     (l_session->stream_data->stream_id == a_frame->hd.stream_id))
                {
                        fprintf(stderr, "Response headers for stream ID=%d:\n", a_frame->hd.stream_id);
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
        nghttp2_session_client_new(&(a_session->session), l_cb, a_session);
        nghttp2_session_callbacks_del(l_cb);
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
        printf("Connecting...\n");

        // Init tls...
        tls_init();

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
        SSL *l_ssl = NULL;
        l_ssl = ssl_connect(l_host, l_port);
        if(!l_ssl)
        {
                printf("Error performing ssl_connect\n");
                return -1;
        }

        // -------------------------------------------
        // Init session...
        // -------------------------------------------
        ngxxx_session *l_session = NULL;
        l_session = (ngxxx_session *)calloc(1, sizeof(ngxxx_session));

        //l_session->stream_data = create_http2_stream_data(uri, &u);

        ngxxx_init_nghttp2_session(l_session);

        // -------------------------------------------
        // Send connection header
        // -------------------------------------------
        //send_client_connection_header(session_data);

        // -------------------------------------------
        // Send Request
        // -------------------------------------------
        //submit_request(session_data);
        //if (session_send(session_data) != 0)
        //{
        //        delete_http2_session_data(session_data);
        //}

#if 0
        struct http_parser_url u;
        char *host;
        uint16_t port;
        int rv;
        SSL_CTX *ssl_ctx;
        struct event_base *evbase;
        http2_session_data *session_data;

        /* Parse the |uri| and stores its components in |u| */
        rv = http_parser_parse_url(uri, strlen(uri), 0, &u);
        if (rv != 0)
        {
                errx(1, "Could not parse URI %s", uri);
        }
        host = strndup(&uri[u.field_data[UF_HOST].off], u.field_data[UF_HOST].len);
        if (!(u.field_set & (1 << UF_PORT)))
        {
                port = 443;
        } else
        {
                port = u.port;
        }

        ssl_ctx = create_ssl_ctx();

        evbase = event_base_new();

        session_data = create_http2_session_data(evbase);
        session_data->stream_data = create_http2_stream_data(uri, &u);

        initiate_connection(evbase, ssl_ctx, host, port, session_data);
        free(host);
        host = NULL;

        event_base_loop(evbase, 0);

        event_base_free(evbase);
        SSL_CTX_free(ssl_ctx);
#endif

        // -------------------------------------------
        // Cleanup...
        // -------------------------------------------
        SSL_shutdown(l_ssl);
        printf("Cleaning up...\n");
        return 0;
}
