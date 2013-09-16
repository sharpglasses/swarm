/*-
 * Copyright (c) 2013 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include "../decode.h"


namespace swarm {

  class DnsDecoder : public Decoder {
  private:
    struct dns_header {
      u_int16_t trans_id_;  // Transaction ID
      u_int16_t flags_;     // Flags
      u_int16_t qd_count_;  // Query Count
      u_int16_t an_count_;  // Answer Count
      u_int16_t ns_count_;  // Authory Count
      u_int16_t ar_count_;  // Additional Record Count
    } __attribute__((packed));

    struct dns_rr_header {
      u_int16_t type_;    // Resource type
      u_int16_t class_;   // Class (basically 0x0001)
    } __attribute__((packed));

    struct dns_ans_header {
      u_int32_t ttl_;     // Cache duration of resouce record
      u_int16_t rd_len_;  // Resource data length
    } __attribute__((packed));

    static const bool DEBUG = false;
    static const u_int16_t RR_QD  = 0;
    static const u_int16_t RR_AN  = 1;
    static const u_int16_t RR_NS  = 2;
    static const u_int16_t RR_AR  = 3;
    static const u_int16_t RR_CNT = 4;

    // flags must be done ntohs ()
    inline static bool has_qr_flag (u_int16_t flags) {
      return ((flags & 0x0001) > 0);
    }

    inline static byte_t * parse_label (byte_t * p, size_t remain,
                                        const byte_t * sp,
                                        const size_t total_len,
                                        std::string * s);


    ev_id EV_DNS_PKT_, EV_TYPE_[4];
    param_id P_ID_;
    param_id DNS_NAME[4];
    param_id DNS_TYPE[4];
    param_id DNS_DATA[4];

  public:
    // VarDnsData for data part of DNS record
    class VarDnsData : public Var {
    private:
      u_int16_t type_;
      byte_t * base_ptr_;
      size_t total_len_;

    public:
      bool repr (std::string *s) const {
        bool rc = false;
        switch (this->type_) {
        case  1: rc = this->ip4 (s); break;  // A
        case 28: rc = this->ip6 (s); break;  // AAAA
        case  2:  // NS
        case  5:  // CNAME
        case  6:  // SOA
        case 12:  // PTR
        case 15:  // MX
          {
            size_t len;
            byte_t * ptr = this->get (&len);
            byte_t * rp;
            rp = DnsDecoder::parse_label (ptr, len, this->base_ptr_,
                                          this->total_len_, s);
            rc = (rp != NULL);
          }
          break;

        default:
          debug (1, "? %d", this->type_);
        }
        return rc;
      }
      void set_data (byte_t * ptr, size_t len, u_int16_t type,
                     byte_t * base_ptr, size_t total_len) {
        this->set (ptr, len);
        this->type_ = type;
        this->base_ptr_ = base_ptr;
        this->total_len_ = total_len;
      }
    };
    class FacDnsData : public VarFactory {
    public:
      Var * New () { return new VarDnsData (); }
    };

    // VarDnsName for data part of DNS record
    class VarDnsName : public Var {
    private:
      byte_t * base_ptr_;
      size_t total_len_;

    public:
      bool repr (std::string *s) const {
        size_t len;
        byte_t * ptr = this->get (&len);
        byte_t * rp;
        rp = DnsDecoder::parse_label (ptr, len, this->base_ptr_,
                                      this->total_len_, s);
        return (rp != NULL);
      }
      void set_data (byte_t * ptr, size_t len, byte_t * base_ptr,
                     size_t total_len) {
        this->set (ptr, len);
        this->base_ptr_ = base_ptr;
        this->total_len_ = total_len;
      }
    };
    class FacDnsName : public VarFactory {
    public:
      Var * New () { return new VarDnsName (); }
    };


    DEF_REPR_CLASS (VarType, FacType);

    explicit DnsDecoder (NetDec * nd) : Decoder (nd) {
      // Assign event name
      this->EV_DNS_PKT_ = nd->assign_event ("dns.packet", "DNS Packet");

      // Assign parameter name
      this->P_ID_  = nd->assign_param ("dns.id", "DNS Transaction ID",
                                       new FacNum ());

      for (size_t i = 0; i < RR_CNT; i++) {
        std::string base, desc;
        switch (i) {
        case RR_QD: base = "qd"; desc = "DNS Question"; break;
        case RR_AN: base = "an"; desc = "DNS Answer RP"; break;
        case RR_NS: base = "ns"; desc = "DNS Authority RP"; break;
        case RR_AR: base = "ar"; desc = "DNS Additional RP"; break;
        default: assert (0);
        }

        std::string ev_name = "dns." + base;
        this->EV_TYPE_[i] = nd->assign_event (ev_name, desc);

        std::string name_key = "dns." + base + "_name";
        std::string type_key = "dns." + base + "_type";
        std::string data_key = "dns." + base + "_data";
        this->DNS_NAME[i] = nd->assign_param (name_key, desc + " Name",
                                              new FacDnsName ());
        this->DNS_TYPE[i] = nd->assign_param (type_key, desc + " Type",
                                              new FacType ());
        this->DNS_DATA[i] = nd->assign_param (data_key, desc + " Data",
                                              new FacDnsData ());
      }
    }
    void setup (NetDec * nd) {
      // No upper decoder is needed
    };

    // Factory function for DnsDecoder
    static Decoder * New (NetDec * nd) { return new DnsDecoder (nd); }

    // Main decoding function.
    bool decode (Property *p) {
      const size_t hdr_len = sizeof (struct dns_header);
      byte_t *base_ptr = p->payload (hdr_len);

      if (base_ptr == NULL) {
        return false;
      }

      struct dns_header * hdr =
        reinterpret_cast<struct dns_header*> (base_ptr);

      p->push_event (this->EV_DNS_PKT_);

      int rr_count[4], rr_delim[4];
      rr_count[RR_QD] = ntohs (hdr->qd_count_);
      rr_count[RR_AN] = ntohs (hdr->an_count_);
      rr_count[RR_NS] = ntohs (hdr->ns_count_);
      rr_count[RR_AR] = ntohs (hdr->ar_count_);
      int rr_total =
        rr_count[RR_QD] + rr_count[RR_AN] + rr_count[RR_NS] + rr_count[RR_AR];

      for (int i = 0; i < 4; i++) {
        if (rr_count[i] > 0) {
          p->push_event (this->EV_TYPE_[i]);
        }
      }

      for (int i = 0; i < 4; i++) {
        rr_delim[i] = (i == 0 ? 0 : (rr_delim[i - 1] + rr_count[i - 1]));
      }

      debug (DEBUG, "trans_id:0x%04X, flags:%04X, qd=%d, an=%d, ns=%d, ar=%d",
             hdr->trans_id_, hdr->flags_, rr_count[RR_QD], rr_count[RR_AN],
             rr_count[RR_NS], rr_count[RR_AR]);

      const size_t total_len = p->remain ();
      byte_t *ptr = p->payload (total_len);
      assert (ptr != NULL);
      const byte_t * ep = base_ptr + hdr_len + total_len;

      p->set (this->P_ID_, &(hdr->trans_id_), sizeof (hdr->trans_id_));

      // parsing resource record
      int target = 0, rr_c = 0;
      for (int c = 0; c < rr_total; c++) {
        while (rr_c >= rr_count[target]) {
          rr_c = 0;
          target++;
          assert (target < RR_CNT);
        }
        rr_c++;

        int remain = ep - ptr;
        // assert (ep - ptr > 0);
        if (ep <= ptr) {
          return false;
        }

        VarDnsName * vn =
          dynamic_cast <VarDnsName*> (p->retain (this->DNS_NAME[target]));
        assert (vn != NULL);
        vn->set_data (ptr, remain, base_ptr, total_len);

        if (NULL == (ptr = DnsDecoder::parse_label (ptr, remain, base_ptr,
                                                    total_len, NULL))) {
          debug (DEBUG, "label parse error");
          break;
        }

        // assert (ep - ptr);
        if (ep <= ptr) {
          return false;
        }

        if (ep - ptr < sizeof (struct dns_rr_header)) {
          debug (DEBUG, "not enough length: %ld", ep - ptr);
          break;
        }
        struct dns_rr_header * rr_hdr =
          reinterpret_cast <struct dns_rr_header*>(ptr);
        ptr += sizeof (struct dns_rr_header);

        // set value
        p->set (this->DNS_TYPE[target], &(rr_hdr->type_),
                sizeof (rr_hdr->type_));

        // has resource data field
        if (c >= rr_count[RR_QD]) {
          if (ep - ptr < sizeof (struct dns_ans_header)) {
            debug (DEBUG, "not enough length: %ld", ep - ptr);
            break;
          }
          struct dns_ans_header * ans_hdr =
            reinterpret_cast<struct dns_ans_header*> (ptr);
          ptr += sizeof (struct dns_ans_header);
          const size_t rd_len = ntohs (ans_hdr->rd_len_);

          if (ep - ptr < rd_len) {
            debug (DEBUG, "not match resource record len(%zd) and remain (%zd)",
                   rd_len, ep - ptr);
            break;
          }

          // set value
          VarDnsData * v = dynamic_cast <VarDnsData*>
            (p->retain (this->DNS_DATA[target]));
          assert (v != NULL);
          v->set_data (ptr, rd_len, htons (rr_hdr->type_), base_ptr, total_len);

          // seek pointer
          ptr += rd_len;
        }
      }

      if (ep != ptr) {
        debug (DEBUG, "fail to parse (remain:%ld)", ep - ptr);
      }

      return true;
    }
  };

  byte_t * DnsDecoder::parse_label (byte_t * p, size_t remain,
                                    const byte_t * sp,
                                    const size_t total_len,
                                    std::string * s) {
    const size_t min_len = 1;
    const size_t dst_len = 2;
    const size_t max_len = 256;
    size_t len = 0;

    bool DEBUG = false;
    if (s) {
      s->erase ();
    }

    byte_t * rp = NULL;

    while (len < max_len) {
      if (remain < min_len) {
        debug (DEBUG, "not enough length: %zd", remain);
        return NULL;
      }

      // jump if needed
      if ((*p & 0xC0) == 0xC0) {
        if (remain < dst_len) {
          debug (DEBUG, "not enough jump destination length: %zd", remain);
          return NULL;
        }

        u_int16_t * h = reinterpret_cast <u_int16_t *>(p);
        u_int16_t jmp = (ntohs (*h) & 0x3FFF);

        if (jmp >= total_len) {
          debug (DEBUG, "invalid jump point: %zd", jmp);
          return NULL;
        }
        if (rp == NULL) {
          rp = p + dst_len;
        }
        p = const_cast<byte_t*> (&(sp[jmp]));
        remain = total_len - (jmp);
      }

      // retain payload
      int data_len = *p;
      if (data_len == 0) {
        return (rp == NULL ? p + 1 : rp);
      }
      if (data_len + min_len >= remain) {
        debug (DEBUG, "invalid data length: %zd (remain:%zd)",
               data_len, remain);
        return NULL;
      }

      if (s) {
        s->append (reinterpret_cast<char*>(p + 1), data_len);
        s->append (".", 1);
      }
      len += data_len;

      p += data_len + 1;
      remain -= data_len + 1;
    }

    // if exiting loop, too log domain name (invalid)
    return NULL;
  }

  bool DnsDecoder::VarType::repr (std::string *s) const {
    u_int16_t type = this->num <u_int16_t> ();
    switch (type) {
    case  1: s->assign ("A"); break;
    case  2: s->assign ("NS"); break;
    case  5: s->assign ("CNAME"); break;
    case  6: s->assign ("SOA"); break;
    case 12: s->assign ("PTR"); break;
    case 15: s->assign ("MX"); break;
    case 28: s->assign ("AAAA"); break;
    default:
      {
        char buf[32];
        snprintf (buf, sizeof (buf), "%u", type);
        s->assign (buf);
      }
      break;
    }
    return true;
  }


  INIT_DECODER (dns, DnsDecoder::New);
}  // namespace swarm
