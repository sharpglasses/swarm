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

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif
#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK 0x9000
#endif
#ifndef ETHERTYPE_WLCCP /* Cisco Wireless LAN Context Control Protocol */
#define ETHERTYPE_WLCCP 0x872d
#endif
#ifndef ETHERTYPE_NETWARE /* Netware IPX/SPX */
#define ETHERTYPE_NETWARE 0x8137
#endif

namespace swarm {    
    class EtherDecoder : public Decoder {
    private:
        static const size_t ETHER_ADDR_LEN = 6;

        struct ether_header
        {
            u_int8_t dst_[ETHER_ADDR_LEN];
            u_int8_t src_[ETHER_ADDR_LEN];
            u_int16_t type_;
        } __attribute__((packed));

      key_t ETHER_SRC;
      key_t ETHER_DST;
      key_t ETHER_TYPE;
      key_t EV_ETHER_PKT;

    public:
      EtherDecoder (Engine * e) : Decoder (e) {
        this->ETHER_SRC = e->assign_var_key ("ether.src");
        this->ETHER_DST = e->assign_var_key ("ether.dst");
        this->ETHER_TYPE = e->assign_var_key ("ether.type");
        this->EV_ETHER_PKT = e->assign_event_key ("ether.packet");
      }

        void decode (Property * prop, Payload * p) {
            const struct ether_header * hdr = 
                static_cast<const struct ether_header*>(p->ptr());

            if (! p->seek (sizeof (struct ether_header))) {
                // invalid header length
                return ;
            }

            // dispatch event
            Record * rec = this->acquire_record ();
            rec->set_var (this->ETHER_SRC, &(hdr->src_), sizeof (hdr->src_), p);
            rec->set_var (this->ETHER_DST, &(hdr->dst_), sizeof (hdr->dst_), p);
            rec->set_var (this->ETHER_TYPE, &(hdr->type_), 
                          sizeof (hdr->type_), p);

            this->dispatch (this->EV_ETHER_PKT, prop, rec);
            rec->release ();

            // emit to a upper layer decoder
            switch (ntohs (hdr->type_)) {
            case ETHERTYPE_ARP:  this->emit (ARP,  prop, p); break;
            case ETHERTYPE_VLAN: this->emit (VLAN, prop, p); break;
            case ETHERTYPE_IP:   this->emit (IPV4, prop, p); break;
            case ETHERTYPE_IPV6: this->emit (IPV6, prop, p); break;
            case ETHERTYPE_LOOPBACK: break; // ignore
            case ETHERTYPE_WLCCP:    break; // ignore
            case ETHERTYPE_NETWARE:  break; // ignore
            }

            return ;
        }
    };
}

