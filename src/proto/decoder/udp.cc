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

namespace swarm {
    class UdpDecoder : public Decoder {
    private:

        struct udp_header
        {
            u_int16_t src_port_;  // source port
            u_int16_t dst_port_;  // destination port
            u_int16_t length_;    // length
            u_int16_t chksum_;	  // checksum
        } __attribute__((packed));

        static const bool DEBUG = false;

      key_t UDP_SRC_PORT;
      key_t UDP_DST_PORT;
      key_t UDP_DATA;
      key_t EV_UDP_PKT;

    public:
        UdpDecoder (Engine * e) : Decoder (e) {
          this->UDP_SRC_PORT = e->assign_var_key ("udp.src_port");
          this->UDP_DST_PORT = e->assign_var_key ("udp.dst_port");
          this->UDP_DATA     = e->assign_var_key ("udp.data");
          this->EV_UDP_PKT = e->assign_event_key ("udp.packet");
        }
        void decode (Property * f, Payload * p) {
            const size_t fixed_len = sizeof (struct udp_header);
            const struct udp_header * hdr =
                static_cast<const struct udp_header*>(p->ptr());

            if (! p->seek (fixed_len)) {
                debug (DEBUG, "invalid header length");
                return ;
            }

            f->set_port (UDP, ntohs (hdr->src_port_), ntohs (hdr->dst_port_));
            debug (DEBUG, "len = %d, sport = %d, dport = %d",
                   ntohs (hdr->length_),
                   ntohs (hdr->src_port_),
                   ntohs (hdr->dst_port_));

            Record * r = this->acquire_record ();

            r->set_var (this->UDP_SRC_PORT, &hdr->src_port_, 
                        sizeof (hdr->src_port_));
            r->set_var (this->UDP_DST_PORT, &hdr->dst_port_, 
                        sizeof (hdr->dst_port_));
            if (p->remain () > 0) {
                r->set_var (this->UDP_DATA, p->ptr (), p->remain (), p);
                debug (DEBUG, "data_len: %zd", p->remain ());
            }

            this->dispatch (this->EV_UDP_PKT, f, r);
            r->release ();

            if (f->src_port () == 53 || f->dst_port () == 53) {
              this->emit (DNS, f, p);
            }

            return ;
        }
    };
}

