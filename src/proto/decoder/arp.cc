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
    class ArpDecoder : public Decoder {
    private:
        struct arp_header
        {
#define ARPHRD_ETHER           1  /* ethernet hardware format */
#define ARPHRD_IEEE802         6  /* token-ring hardware format */
#define ARPHRD_FRELAY         15  /* frame relay hardware format */
#define ARPHRD_IEEE1394       24  /* IEEE1394 hardware address */
#define ARPHRD_IEEE1394_EUI64 27  /* IEEE1394 EUI-64 */

#define ARPOP_REQUEST    1      /* request to resolve address */
#define ARPOP_REPLY      2      /* response to previous request */
#define ARPOP_REVREQUEST 3      /* request protocol address given hardware */
#define ARPOP_REVREPLY   4      /* response giving protocol address */
#define ARPOP_INVREQUEST 8      /* request to identify peer */
#define ARPOP_INVREPLY   9      /* response identifying peer */

            u_int16_t hw_addr_fmt_;
            u_int16_t pr_addr_fmt_;
            u_int8_t  hw_addr_len_;
            u_int8_t  pr_addr_len_;
            u_int16_t op_;
        } __attribute__((packed));

        static const bool DEBUG = false;
      key_t ARP_OP;
      key_t ARP_SRC_HW;
      key_t ARP_DST_HW;
      key_t ARP_SRC_PR;
      key_t ARP_DST_PR;
      key_t EV_ARP_PKT;

    public:
        ArpDecoder (Engine * e) : Decoder (e) {
          this->ARP_OP     = e->assign_var_key ("arp.op");
          this->ARP_SRC_HW = e->assign_var_key ("arp.src_hw");
          this->ARP_DST_HW = e->assign_var_key ("arp.dst_hw");
          this->ARP_SRC_PR = e->assign_var_key ("arp.src_pr");
          this->ARP_DST_PR = e->assign_var_key ("arp.dst_pr");
          this->EV_ARP_PKT = e->assign_event_key ("arp.packet");
        }
        void decode (Property * prop, Payload * p) {
            const size_t fixed_len = sizeof (struct arp_header);
            const struct arp_header * hdr = 
                static_cast<const struct arp_header*>(p->ptr());

            if (! p->seek (fixed_len)) {
                debug (DEBUG, "invalid header length");
                return ;
            }
            
            bool rc = true;            

            const void * src_hw = p->ptr ();
            rc &= p->seek (hdr->hw_addr_len_);
            const void * src_pr = p->ptr ();
            rc &= p->seek (hdr->pr_addr_len_);
            const void * dst_hw = p->ptr ();
            rc &= p->seek (hdr->hw_addr_len_);
            const void * dst_pr = p->ptr ();
            rc &= p->seek (hdr->pr_addr_len_);

            if (! rc) {
                debug (DEBUG, "invalid data length");
                return;
            }

            Record * rec = this->acquire_record ();

            rec->set_var (this->ARP_OP, &(hdr->op_), sizeof (hdr->op_), p);
            rec->set_var (this->ARP_SRC_HW, src_hw, hdr->hw_addr_len_, p);
            rec->set_var (this->ARP_DST_HW, dst_hw, hdr->hw_addr_len_, p);
            rec->set_var (this->ARP_SRC_PR, src_pr, hdr->pr_addr_len_, p);
            rec->set_var (this->ARP_DST_PR, dst_pr, hdr->pr_addr_len_, p);

            this->dispatch (this->EV_ARP_PKT, prop, rec);

            rec->release ();

            debug (DEBUG, "op = %d, hw_fmt = %d, proto_fmt = %d", 
                   ntohs (hdr->op_), 
                   ntohs (hdr->hw_addr_fmt_),
                   ntohs (hdr->pr_addr_fmt_));
            
            return ;
        }
    };
}

