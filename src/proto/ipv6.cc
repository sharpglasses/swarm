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

#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */


namespace swarm {

  class Ipv6Decoder : public Decoder {
  private:
    static const u_int8_t PROTO_ICMP  = 1;
    static const u_int8_t PROTO_TCP   = 6;
    static const u_int8_t PROTO_UDP   = 17;
    static const u_int8_t PROTO_IPV6  = 41;
    static const u_int8_t PROTO_ICMP6 = 58;

    struct ipv6_header {
      u_int32_t flags_;      // version, traffic class, flow label
      u_int16_t data_len_;   // dat length
      u_int8_t  next_hdr_;   // next header
      u_int8_t  hop_limit_;  // hop limit
      u_int32_t src_[4];     // source address
      u_int32_t dst_[4];     // dest address
    } __attribute__((packed));

    ev_id EV_IPV6_PKT_;
    param_id P_PROTO_, P_SRC_, P_DST_, P_DLEN_, P_PL_;
    dec_id D_ICMP_;
    dec_id D_UDP_;
    dec_id D_TCP_;
    dec_id D_ICMP6_;

  public:
    DEF_REPR_CLASS (Proto, FacProto);

    explicit Ipv6Decoder (NetDec * nd) : Decoder (nd) {
      this->EV_IPV6_PKT_ = nd->assign_event ("ipv6.packet", "Ipv6 Packet");
      this->P_PROTO_ = nd->assign_param ("ipv6.proto", "Ipv6 Protocol",
                                         new FacProto ());
      this->P_SRC_   = nd->assign_param ("ipv6.src", "Ipv6 Source Address",
                                         new FacIPv6 ());
      this->P_DST_   = nd->assign_param ("ipv6.dst", "Ipv6 Destination Address",
                                         new FacIPv6 ());
      this->P_DLEN_  = nd->assign_param ("ipv6.data_len", "Ipv6 Data Length",
                                         new FacNum());
      this->P_PL_    = nd->assign_param ("ipv6.payload", "Ipv6 Data Payload");
    }
    void setup (NetDec * nd) {
      this->D_ICMP_  = nd->lookup_dec_id ("icmp");
      this->D_ICMP6_ = nd->lookup_dec_id ("icmp6");
      this->D_UDP_   = nd->lookup_dec_id ("udp");
      this->D_TCP_   = nd->lookup_dec_id ("tcp");
    };

    static Decoder * New (NetDec * nd) { return new Ipv6Decoder (nd); }

    bool decode (Property *p) {
      const size_t hdr_len = sizeof (struct ipv6_header);
      auto hdr = reinterpret_cast <struct ipv6_header *>
        (p->payload (hdr_len));

      if (hdr == NULL) {
        return false;
      }

      // set data to property
      p->set (this->P_PROTO_, &(hdr->next_hdr_), sizeof (hdr->next_hdr_));
      p->set (this->P_SRC_,   &(hdr->src_), sizeof (hdr->src_));
      p->set (this->P_DST_,   &(hdr->dst_), sizeof (hdr->dst_));
      p->set (this->P_DLEN_,  &(hdr->data_len_), sizeof (hdr->data_len_));

      size_t data_len = htons (hdr->data_len_);
      auto ip_data = p->refer (data_len);
      if (ip_data) {
        p->set (this->P_PL_, ip_data, data_len);
      }

      // push event
      p->push_event (this->EV_IPV6_PKT_);

      // ToDo(masa): Reassembling IP fragmentation
      assert (sizeof (hdr->src_) == sizeof (hdr->dst_));
      p->set_addr (&(hdr->src_), &(hdr->dst_), hdr->next_hdr_,
                   sizeof (hdr->src_));

      // call next decoder
      switch (hdr->next_hdr_) {
      case PROTO_ICMP:  this->emit (this->D_ICMP_,  p); break;
      case PROTO_TCP:   this->emit (this->D_TCP_,   p); break;
      case PROTO_UDP:   this->emit (this->D_UDP_,   p); break;
      case PROTO_ICMP6: this->emit (this->D_ICMP6_, p); break;
      }

      return true;
    }
  };

  bool Ipv6Decoder::Proto::repr (std::string *s) const {
    u_int8_t proto = this->num <u_int8_t> ();
    switch (proto) {
    case PROTO_ICMP:  *s = "ICMP";    break;
    case PROTO_TCP:   *s = "TCP";     break;
    case PROTO_UDP:   *s = "UDP";     break;
    case PROTO_IPV6:  *s = "IPv6";    break;
    case PROTO_ICMP6: *s = "ICMPv6";  break;
    default:            *s = "unknown"; break;
    }
    return true;
  }

  INIT_DECODER (ipv6, Ipv6Decoder::New);
}  // namespace swarm