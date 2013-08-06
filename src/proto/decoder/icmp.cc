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
    class IcmpDecoder : public Decoder {
    private:

        struct icmp_header
        {
            u_int8_t type_;
#ifndef ICMP_ECHOREPLY
#define	ICMP_ECHOREPLY		0		/* echo reply */
#endif
#ifndef ICMP_UNREACH
#define	ICMP_UNREACH		3		/* dest unreachable */
#endif
#ifndef ICMP_REDIRECT
#define	ICMP_REDIRECT		5		/* shorter route, codes: */
#endif
#ifndef ICMP_ECHO
#define	ICMP_ECHO		8		/* echo service */
#endif
            u_int8_t code_;
            u_int16_t chksum_;		/* ICMP Checksum */
        } __attribute__((packed));

        static const bool DEBUG = false;

      key_t ICMP_TYPE;
      key_t ICMP_CODE;
      key_t EV_ICMP_PKT ;

    public:
        IcmpDecoder (Engine * e) : Decoder (e) {
          this->ICMP_TYPE = e->assign_var_key ("icmp.type");
          this->ICMP_CODE = e->assign_var_key ("icmp.code");
          this->EV_ICMP_PKT = e->assign_event_key ("icmp.packet");
        }
        void decode (Property * prop, Payload * p) {
            const size_t fixed_len = sizeof (struct icmp_header);
            const struct icmp_header * hdr = 
                static_cast<const struct icmp_header*>(p->ptr());
            if (! p->seek (fixed_len)) {
                debug (DEBUG, "invalid header length");
                return ;
            }


            debug (DEBUG, "type = %d, code = %d", hdr->type_, hdr->code_);

            // dispatch event
            Record * rec = this->acquire_record ();
            rec->set_var (this->ICMP_TYPE, &(hdr->type_), sizeof (hdr->type_), p);
            rec->set_var (this->ICMP_CODE, &(hdr->code_), sizeof (hdr->code_), p);
            this->dispatch (this->EV_ICMP_PKT, prop, rec);
            rec->release ();

            /*
            if (hdr->type_ == 3 && hdr->code_ == 3) {
                this->emit (IPV4, prop, p);
            }
            */

            return ;
        }
    };
}

