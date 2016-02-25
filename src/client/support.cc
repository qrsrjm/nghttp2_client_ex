//: ----------------------------------------------------------------------------
//: \file:    support.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    02/20/2016
//: ----------------------------------------------------------------------------

//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "support.h"
#include "http_parser/http_parser.h"

#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

//: ----------------------------------------------------------------------------
//: \details: Host info
//: ----------------------------------------------------------------------------
struct host_info {
        struct sockaddr_storage m_sa;
        int m_sa_len;
        int m_sock_family;
        int m_sock_type;
        int m_sock_protocol;
        host_info():
                m_sa(),
                m_sa_len(16),
                m_sock_family(AF_INET),
                m_sock_type(SOCK_STREAM),
                m_sock_protocol(IPPROTO_TCP)
        {((struct sockaddr_in *)(&m_sa))->sin_family = AF_INET;}
};

//: ----------------------------------------------------------------------------
//: \details: slow resolution
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static int32_t nlookup(const std::string &a_host, uint16_t a_port, host_info &ao_host_info)
{
        // Initialize...
        ao_host_info.m_sa_len = sizeof(ao_host_info.m_sa);
        memset((void*) &(ao_host_info.m_sa), 0, ao_host_info.m_sa_len);

        // ---------------------------------------
        // get address...
        // ---------------------------------------
        struct addrinfo l_hints;
        memset(&l_hints, 0, sizeof(l_hints));
        l_hints.ai_family = PF_UNSPEC;
        l_hints.ai_socktype = SOCK_STREAM;
        char portstr[10];
        snprintf(portstr, sizeof(portstr), "%d", (int) a_port);
        struct addrinfo* l_addrinfo;

        int l_gaierr;
        l_gaierr = getaddrinfo(a_host.c_str(), portstr, &l_hints, &l_addrinfo);
        if (l_gaierr != 0)
        {
                //printf("Error getaddrinfo '%s': %s\n",
                //           a_host.c_str(), gai_strerror(l_gaierr));
                return -1;
        }

        // Find the first IPv4 and IPv6 entries.
        struct addrinfo* l_addrinfo_v4 = NULL;
        struct addrinfo* l_addrinfo_v6 = NULL;
        for (struct addrinfo* i_addrinfo = l_addrinfo;
             i_addrinfo != (struct addrinfo*) 0;
             i_addrinfo = i_addrinfo->ai_next)
        {
                switch (i_addrinfo->ai_family)
                {
                case AF_INET:
                {
                        if (l_addrinfo_v4 == (struct addrinfo*) 0)
                                l_addrinfo_v4 = i_addrinfo;
                        break;
                }
                case AF_INET6:
                {
                        if (l_addrinfo_v6 == (struct addrinfo*) 0)
                                l_addrinfo_v6 = i_addrinfo;
                        break;
                }
                }
        }
        //printf("RESOLVE:\n");
        // If there's an IPv4 address, use that, otherwise try IPv6.
        if (l_addrinfo_v4 != NULL)
        {
                if (sizeof(ao_host_info.m_sa) < l_addrinfo_v4->ai_addrlen)
                {
                        printf("Error %s - sockaddr too small (%lu < %lu)\n",
                                   a_host.c_str(),
                              (unsigned long) sizeof(ao_host_info.m_sa),
                              (unsigned long) l_addrinfo_v4->ai_addrlen);
                        return -1;
                }
                ao_host_info.m_sock_family = l_addrinfo_v4->ai_family;
                ao_host_info.m_sock_type = l_addrinfo_v4->ai_socktype;
                ao_host_info.m_sock_protocol = l_addrinfo_v4->ai_protocol;
                ao_host_info.m_sa_len = l_addrinfo_v4->ai_addrlen;
                //printf("memmove: addrlen: %d\n", l_addrinfo_v4->ai_addrlen);
                //ns_hlx::mem_display((const uint8_t *)l_addrinfo_v4->ai_addr,
                //                   l_addrinfo_v4->ai_addrlen);
                //show_host_info();
                memmove(&(ao_host_info.m_sa),
                        l_addrinfo_v4->ai_addr,
                        l_addrinfo_v4->ai_addrlen);
                // Set the port
                ((sockaddr_in *)(&(ao_host_info.m_sa)))->sin_port = htons(a_port);
                freeaddrinfo(l_addrinfo);
        }
        else if (l_addrinfo_v6 != NULL)
        {
                if (sizeof(ao_host_info.m_sa) < l_addrinfo_v6->ai_addrlen)
                {
                        printf("Error %s - sockaddr too small (%lu < %lu)\n",
                                   a_host.c_str(),
                              (unsigned long) sizeof(ao_host_info.m_sa),
                              (unsigned long) l_addrinfo_v6->ai_addrlen);
                        return -1;
                }
                ao_host_info.m_sock_family = l_addrinfo_v6->ai_family;
                ao_host_info.m_sock_type = l_addrinfo_v6->ai_socktype;
                ao_host_info.m_sock_protocol = l_addrinfo_v6->ai_protocol;
                ao_host_info.m_sa_len = l_addrinfo_v6->ai_addrlen;
                //printf("memmove: addrlen: %d\n", l_addrinfo_v6->ai_addrlen);
                //ns_hlx::mem_display((const uint8_t *)l_addrinfo_v6->ai_addr,
                //                    l_addrinfo_v6->ai_addrlen);
                //show_host_info();
                memmove(&ao_host_info.m_sa,
                        l_addrinfo_v6->ai_addr,
                        l_addrinfo_v6->ai_addrlen);
                // Set the port
                ((sockaddr_in6 *)(&(ao_host_info.m_sa)))->sin6_port = htons(a_port);
                freeaddrinfo(l_addrinfo);
        }
        else
        {
                printf("Error no valid address found for host %s\n",
                           a_host.c_str());
                return -1;
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void tls_init(void)
{
        // Initialize the OpenSSL library
        SSL_library_init();

        // Bring in and register error messages
        ERR_load_crypto_strings();
        SSL_load_error_strings();

        // TODO Deprecated???
        //SSLeay_add_tls_algorithms();
        OpenSSL_add_all_algorithms();

        // We MUST have entropy, or else there's no point to crypto.
        if (!RAND_poll())
        {
                return;
        }

        // TODO Old method???
#if 0
        // Random seed
        if (! RAND_status())
        {
                unsigned char bytes[1024];
                for (size_t i = 0; i < sizeof(bytes); ++i)
                        bytes[i] = random() % 0xff;
                RAND_seed(bytes, sizeof(bytes));
        }
#endif
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t parse_url(const std::string &a_url, std::string &ao_host, uint16_t &ao_port, std::string &ao_path)
{
        std::string l_url_fixed = a_url;
        // Find scheme prefix "://"
        if(a_url.find("://", 0) == std::string::npos)
        {
                l_url_fixed = "http://" + a_url;
        }
        http_parser_url l_url;
        http_parser_url_init(&l_url);
        int l_status;
        l_status = http_parser_parse_url(l_url_fixed.c_str(), l_url_fixed.length(), 0, &l_url);
        if(l_status != 0)
        {
                printf("Error parsing url: %s\n", l_url_fixed.c_str());
                // TODO get error msg from http_parser
                return -1;
        }
        // Set no port
        bool l_is_ssl = true;
        ao_port = 0;
        for(uint32_t i_part = 0; i_part < UF_MAX; ++i_part)
        {
                if(l_url.field_data[i_part].len &&
                  // TODO Some bug with parser -parsing urls like "http://127.0.0.1" sans paths
                  ((l_url.field_data[i_part].len + l_url.field_data[i_part].off) <= l_url_fixed.length()))
                {
                        switch(i_part)
                        {
                        case UF_SCHEMA:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                //printf("l_part: %s\n", l_part.c_str());
                                if(l_part == "http")
                                {
                                        l_is_ssl = false;
                                }
                                else if(l_part == "https")
                                {
                                        l_is_ssl = true;
                                }
                                else
                                {
                                        printf("Error schema[%s] is unsupported\n", l_part.c_str());
                                        return -1;
                                }
                                break;
                        }
                        case UF_HOST:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                ao_host = l_part;
                                break;
                        }
                        case UF_PORT:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                ao_port = (uint16_t)strtoul(l_part.c_str(), NULL, 10);
                                break;
                        }
                        case UF_PATH:
                        {
                                std::string l_part = l_url_fixed.substr(l_url.field_data[i_part].off, l_url.field_data[i_part].len);
                                ao_path = l_part;
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
        }
        if(!ao_port)
        {
                if(l_is_ssl) ao_port = 443;
                else ao_port = 80;
        }
        if (l_status != 0)
        {
                printf("Error parsing url: %s.\n", l_url_fixed.c_str());
                return -1;
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
SSL *ssl_connect(const std::string &a_host, uint16_t a_port)
{
        // Lookup host
        int32_t l_s;
        host_info l_hi;
        l_s = nlookup(a_host, a_port, l_hi);
        if(l_s != 0)
        {
                printf("Error performing nslookup host: %s port: %u\n",a_host.c_str(), a_port);
                return NULL;
        }

        // tcp socket
        int l_fd;
        l_fd = ::socket(l_hi.m_sock_family,
                        l_hi.m_sock_type,
                        l_hi.m_sock_protocol);
        if (l_fd < 0)
        {
                printf("Error creating socket. Reason: %s\n", ::strerror(errno));
                return NULL;
        }

        // connect
        l_s = ::connect(l_fd,
                        ((struct sockaddr*) &(l_hi.m_sa)),
                        (l_hi.m_sa_len));
        if (l_s < 0)
        {
                printf("Error performing connect. Reason: %s\n", ::strerror(errno));
                return NULL;
        }

        printf("Connected\n");
        // ssl ctx
        SSL_CTX *l_ctx;
        l_ctx = SSL_CTX_new(SSLv23_client_method());
        // leaks...
        if (l_ctx == NULL)
        {
                ERR_print_errors_fp(stderr);
                printf("SSL_CTX_new Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
                return NULL;
        }
        // No validation... for now...

        // Create TLS Context
        SSL *l_tls = NULL;
        l_tls = ::SSL_new(l_ctx);
        // TODO Check for NULL

        ::SSL_set_fd(l_tls, l_fd);
        // TODO Check for Errors

        // ssl_connect
        l_s = SSL_connect(l_tls);
        if (l_s <= 0)
        {
                printf("Error performing SSL_connect.\n");
                // TODO Reason...
                return NULL;
        }

        return l_tls;
}
