/**********************************************************************

Copyright (c) 2011 Masa Mizutani <mizutani@sfc.wide.ad.jp>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

***********************************************************************/

#include "decode.h"

#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP   1
#endif
#ifndef IPPROTO_TCP   
#define IPPROTO_TCP    6
#endif
#ifndef IPPROTO_UDP   
#define IPPROTO_UDP   17
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6  41
#endif
#ifndef IPPROTO_ICMP6
#define IPPROTO_ICMP6 58
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE  59
#endif


namespace swarm {    
    class IPv4Decoder : public Decoder {
    private:

        struct ipv4_header
        {
#ifdef __SWARM_BIG_ENDIAN__
            u_int8_t ver_:4;
            u_int8_t hdrlen_:4;
#else
#ifdef __SWARM_LITTLE_ENDIAN__
            u_int8_t hdrlen_:4;
            u_int8_t ver_:4;
#else
#error
#endif
#endif
            u_int8_t tos_;
            u_int16_t total_len_;	/* total length */
            u_int16_t id_;
            u_int16_t offset_;	/* fragment offset */
            u_int8_t ttl_;		/* Time To Live */
            u_int8_t proto_;	/* L4 Protocol */
            u_int16_t chksum_;	/* ip header check sum */
            u_int32_t src_;		/* source ip address */
            u_int32_t dst_;		/* destination ip address */
        } __attribute__((packed));

        static const bool DEBUG = false;
      key_t IPV4_SRC;
      key_t IPV4_DST;
      key_t IPV4_PROTO;
      key_t IPV4_TTL;
      key_t IPV4_TOTAL;
      key_t EV_IPV4_PKT;
      key_t EV_IPV4_FRAGMENT;

    public:
        IPv4Decoder (Engine * e) : Decoder (e) {
          this->IPV4_SRC   = e->assign_var_key ("ipv4.src");
          this->IPV4_DST   = e->assign_var_key ("ipv4.dst");
          this->IPV4_PROTO = e->assign_var_key ("ipv4.proto");
          this->IPV4_TTL   = e->assign_var_key ("ipv4.ttl");
          this->IPV4_TOTAL = e->assign_var_key ("ipv4.total");
          this->EV_IPV4_PKT      = e->assign_event_key ("ipv4.packet");
          this->EV_IPV4_FRAGMENT = e->assign_event_key ("ipv4.fragment");
        }

        void decode (Property * prop, Payload * p) {
            const size_t fixed_len = sizeof (struct ipv4_header);
            const struct ipv4_header * hdr = 
                static_cast<const struct ipv4_header*>(p->ptr());
            if (! p->seek (sizeof (struct ipv4_header))) {
                debug (DEBUG, "invalid header length");
                return ;
            }

            const size_t hdr_len = hdr->hdrlen_ << 2;
            if (hdr_len > fixed_len && ! p->seek (hdr_len - fixed_len)) { 
                debug (DEBUG, "not matched total length and actual size "
                       " (header length:%zd, remain:%zd)", 
                       hdr_len, p->remain ());
                return ;
            }

            prop->set_address (AF_INET, &(hdr->src_), &(hdr->dst_));
            debug (DEBUG, "ver = %d, len = %zd, proto = %d", 
                   hdr->ver_, hdr_len, hdr->proto_);

            p->adjust (ntohs (hdr->total_len_) - hdr_len);

            // dispatch event            
            Record * rec = this->acquire_record ();

            rec->set_var (this->IPV4_SRC, &(hdr->src_), sizeof (hdr->src_), p);
            rec->set_var (this->IPV4_DST, &(hdr->dst_), sizeof (hdr->dst_), p);
            rec->set_var (this->IPV4_PROTO, &(hdr->proto_), 
                          sizeof (hdr->proto_), p);
            rec->set_var (this->IPV4_TTL, &(hdr->ttl_), sizeof (hdr->ttl_), p); 
            rec->set_var (this->IPV4_TOTAL, &(hdr->total_len_), 
                          sizeof (hdr->total_len_), p); 

            this->dispatch (this->EV_IPV4_PKT, prop, rec);
            rec->release ();

            // emit to a upper layer decoder
            switch (hdr->proto_) {
            case IPPROTO_TCP:   this->emit (TCP,   prop, p); break;
            case IPPROTO_UDP:   this->emit (UDP,   prop, p); break;
            case IPPROTO_ICMP:  this->emit (ICMP,  prop, p); break;
            case IPPROTO_ICMP6: this->emit (ICMP6, prop, p); break;
            case IPPROTO_IPV6:  this->emit (IPV6,  prop, p); break;
            }
            
            return ;
        }
    };
}

