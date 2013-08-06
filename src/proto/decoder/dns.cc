/**********************************************************************

Copyright (c) 2012 Masa Mizutani <mizutani@sfc.wide.ad.jp>
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
  class DnsDecoder : public Decoder {
  private:

    struct dns_header {
      u_int16_t trans_id_; // Transaction ID
      u_int16_t flags_;    // Flags
      u_int16_t qd_count_; // Query Count
      u_int16_t an_count_; // Answer Count
      u_int16_t ns_count_; // Authory Count
      u_int16_t ar_count_; // Additional Record Count
    } __attribute__((packed));

    struct dns_rr_header {
      u_int16_t type_;   // Resource type
      u_int16_t class_;  // Class (basically 0x0001)
    } __attribute__((packed));

    struct dns_ans_header {
      u_int32_t ttl_;    // Cache duration of resouce record
      u_int16_t rd_len_; // Resource data length
    } __attribute__((packed));

    static const bool DEBUG = true;
    key_t DNS_QR;
    key_t DNS_ID;
    key_t DNS_NAME[4];
    key_t DNS_TYPE[4];
    key_t DNS_DATA[4];
    key_t EV_DNS_PKT;
    enum {
      RR_QD = 0,
      RR_AN = 1,
      RR_NS = 2,
      RR_AR = 3,
      RR_CNT = 4,
    };

    // flags must be done ntohs ()
    inline static bool has_qr_flag (u_int16_t flags) {
      return ((flags & 0x0001) > 0);
    }

    inline static byte_t * parse_label (byte_t * p, size_t remain, 
                                        const byte_t * sp, const size_t total_len,
                                        std::string * s) {
      *s = "";
      byte_t * rp = NULL; 

      for (;;) {
        if (remain < 2) {
          debug (DEBUG, "not enough length: %d", remain);
          return NULL;
        }

        if ((*p & 0xC0) == 0xC0) {
          u_int16_t * h = reinterpret_cast <u_int16_t *>(p);
          u_int16_t jmp = (ntohs (*h) & 0x3FFF);

          if (jmp >= total_len) {
            debug (DEBUG, "invalid jump point: %d", jmp);
            return NULL;
          }
          if (rp == NULL) {
            rp = p + 2;
          }
          p = const_cast<byte_t*> (&(sp[jmp]));
          remain = total_len - (jmp);          
        }

        int data_len = *p;
        if (data_len == 0) {
          return (rp == NULL ? p + 1 : rp);
        }
        if (data_len + 2 >= remain) {
          debug (DEBUG, "invalid data length: %d (remain:%d)", data_len, remain);
          return NULL;
        }

        s->append (reinterpret_cast<char*>(p + 1), data_len);
        s->append (".", 1);

        p += data_len + 1;
        remain -= data_len + 1;
      }
    }

  public:
    DnsDecoder (Engine * e) : Decoder (e) {
      this->DNS_QR = e->assign_var_key ("dns.qr");
      this->DNS_ID = e->assign_var_key ("dns.id");
      for (int i = 0; i < RR_CNT; i++) {
        std::string base;
        switch (i) {
        case RR_QD: base = "qd"; break;
        case RR_AN: base = "an"; break;
        case RR_NS: base = "ns"; break;
        case RR_AR: base = "ar"; break; 
        default: assert (0);
        }

        std::string name_key = "dns." + base + "_name";
        std::string type_key = "dns." + base + "_type";
        std::string data_key = "dns." + base + "_data";
        this->DNS_NAME[i] = e->assign_var_key (name_key);
        this->DNS_TYPE[i] = e->assign_var_key (type_key);
        this->DNS_DATA[i] = e->assign_var_key (data_key);
      }
      this->EV_DNS_PKT = e->assign_event_key ("dns.packet");

    }

    void decode (Property * f, Payload * p) {
      const size_t fixed_len = sizeof (struct dns_header);
      const struct dns_header * hdr =
        static_cast<const struct dns_header*>(p->ptr());
      const byte_t * base_ptr = static_cast<const byte_t *>(p->ptr());
      const size_t total_len = p->remain ();
      
      if (! p->seek (fixed_len)) {
        debug (DEBUG, "invalid header length");
        return ;
      }

      Record * r = this->acquire_record ();

      int rr_count[4], rr_delim[4];
      rr_count[RR_QD] = ntohs (hdr->qd_count_);
      rr_count[RR_AN] = ntohs (hdr->an_count_);
      rr_count[RR_NS] = ntohs (hdr->ns_count_);
      rr_count[RR_AR] = ntohs (hdr->ar_count_);
      int rr_total = rr_count[RR_QD] + rr_count[RR_AN] + rr_count[RR_NS] + rr_count[RR_AR];
      for (int i = 0; i < 4; i++) {
        rr_delim[i] = (i == 0 ? 0 : (rr_delim[i - 1] + rr_count[i - 1]));
      }

      debug (DEBUG, "trans_id:0x%04X, flags:%04X, qd=%d, an=%d, ns=%d, ar=%d",
             hdr->trans_id_, hdr->flags_, rr_count[RR_QD], rr_count[RR_AN], 
             rr_count[RR_NS], rr_count[RR_AR]);

      byte_t * ptr = static_cast<byte_t*>(const_cast<void*>(p->ptr ()));
      const byte_t * ep = base_ptr + total_len;
      
      r->set_var (this->DNS_ID, &(hdr->trans_id_), sizeof (hdr->trans_id_), p);

      // parsing resource record
      int target = 0;
      int rr_c = 0;
      for (int c = 0; c < rr_total; c++) { 
        while (rr_c >= rr_count[target]) {
          rr_c = 0;
          target++;
          assert (target < RR_CNT);
        }
        rr_c++;

        
        int remain = ep - ptr;
        assert (ep - ptr > 0);

        std::string s;
        if (NULL == (ptr = DnsDecoder::parse_label (ptr, remain, base_ptr,
                                                    total_len, &s))) {
          debug (DEBUG, "label parse error");
          break;
        }

        debug (DEBUG, "name=\"%s\"", s.c_str ());
        assert (ep - ptr);

        if (ep - ptr < sizeof (struct dns_rr_header)) {
          debug (DEBUG, "not enough length: %d", ep - ptr);
          break;
        }
        struct dns_rr_header * rr_hdr = 
          reinterpret_cast <struct dns_rr_header*>(ptr);
        ptr += sizeof (struct dns_rr_header);

        // set value
        debug (1, "target:%d, %s", target, s.c_str ());
        r->set_var (this->DNS_NAME[target], s.c_str (), s.length ());
        r->set_var (this->DNS_TYPE[target], &(rr_hdr->type_), sizeof (rr_hdr->type_), p);

        // has resource data field
        if (c >= rr_count[RR_QD]) {
          if (ep - ptr < sizeof (struct dns_ans_header)) {
            debug (DEBUG, "not enough length: %d", ep - ptr);
            break;
          }
          struct dns_ans_header * ans_hdr = 
            reinterpret_cast<struct dns_ans_header*> (ptr);
          ptr += sizeof (struct dns_ans_header);
          const size_t rd_len = ntohs (ans_hdr->rd_len_);
          
          if (ep - ptr < rd_len) {
            debug (DEBUG, "not match resource record len(%d) and remain (%d)",
                   rd_len, ep - ptr);
            break;
          }

          // set value
          r->set_var (this->DNS_DATA[target], ptr, rd_len - 1, p);

          // seek pointer
          ptr += rd_len;
        }
      }

      if (ep != ptr) {
        debug (DEBUG, "fail to parse (remain:%d)", ep - ptr);
      }

      this->dispatch (this->EV_DNS_PKT, f, r);
      r->release ();

      return ;
    }
  };
}

