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
    class IPv6Decoder : public Decoder {
    private:
        struct ipv6_header
        {
            u_int32_t flags_;     // version, traffic class, flow label 
            u_int16_t total_len_; // total length 
            u_int8_t  next_hdr_;  // next header 
            u_int8_t  hop_limit_; // hop limit 
            u_int32_t src_[4];    // source address 
            u_int32_t dst_[4];    // dest address 
        } __attribute__((packed));


#ifdef __SWARM_LITTLE_ENDIAN__
        inline u_int32_t get_version (const struct ipv6_header * ip6h) {
            return ((htonl(ip6h->flags_) & 0xF0000000) >> 28);
        }
        inline u_int32_t get_tf_class (const struct ipv6_header * ip6h) {
            return ((htonl(ip6h->flags_) & 0x0FF00000) >> 20);
        }
        inline u_int32_t get_flow_label (const struct ipv6_header * ip6h) {
            return ((htonl(ip6h->flags_) & 0x000FFFFF));
        }
#endif
#ifdef __SWARM_BIG_ENDIAN__
        inline u_int32_t get_version (const struct ipv6_header * ip6h) {
            return ((ip6h->flags_ & 0xF0000000) >> 28);
        }
        inline u_int32_t get_tf_class (const struct ipv6_header * ip6h) {
            return ((ip6h->flags_ & 0x0FF00000) >> 20);
        }
        inline u_int32_t get_flow_label (const struct ipv6_header * ip6h) {
            return ((ip6h->flags_ & 0x000FFFFF));
        }
#endif

        static const bool DEBUG = false;

      key_t IPV6_SRC ;
      key_t IPV6_DST ;
      key_t IPV6_NEXT ;
      key_t IPV6_TOTAL;
      key_t EV_IPV6_PKT;

    public:
        IPv6Decoder (Engine * e) : Decoder (e) {
          this->IPV6_SRC = e->assign_var_key ("ipv6.src");
          this->IPV6_DST = e->assign_var_key ("ipv6.dst");
          this->IPV6_NEXT = e->assign_var_key ("ipv6.next");
          this->IPV6_TOTAL = e->assign_var_key ("ipv6.total");
          this->EV_IPV6_PKT = e->assign_event_key ("ipv6.packet");
        }

        void decode (Property * prop, Payload * p) {
            const size_t fixed_len = sizeof (struct ipv6_header);
            const struct ipv6_header * hdr = 
                static_cast<const struct ipv6_header*>(p->ptr());

            if (! p->seek (fixed_len)) {
                debug (DEBUG, "invalid header length");
                return ;
            }

            prop->set_address (AF_INET6, hdr->src_, hdr->dst_);
            debug (DEBUG, "ver = %d, proto = %d", 
                   get_version (hdr), hdr->next_hdr_);

            p->adjust (ntohs (hdr->total_len_));

            // dispatch event
            Record * rec = this->acquire_record ();

            rec->set_var (this->IPV6_SRC, &(hdr->src_), sizeof (hdr->src_), p);
            rec->set_var (this->IPV6_DST, &(hdr->dst_), sizeof (hdr->dst_), p);
            rec->set_var (this->IPV6_NEXT, &(hdr->next_hdr_), 
                          sizeof (hdr->next_hdr_), p);
            rec->set_var (this->IPV6_TOTAL, &(hdr->total_len_), 
                          sizeof (hdr->total_len_), p);  

            this->dispatch (this->EV_IPV6_PKT, prop, rec);
            rec->release ();

            // emit to a upper layer decoder
            switch (hdr->next_hdr_) {
            case IPPROTO_TCP:   this->emit (TCP, prop, p);   break;
            case IPPROTO_UDP:   this->emit (UDP, prop, p);   break;
            case IPPROTO_ICMP:  this->emit (ICMP, prop, p);  break;
            case IPPROTO_ICMP6: this->emit (ICMP6, prop, p); break;
            case IPPROTO_IPV6:  this->emit (IPV6, prop, p);  break;
            }
            
            return ;
        }
    };
}

