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

#include <sstream>
#include "../decode.h"


namespace swarm {

  class TcpDecoder : public Decoder {
  private:
    struct tcp_header {
      u_int16_t src_port_;  // source port
      u_int16_t dst_port_;  // destination port
      u_int32_t seq_;       // tcp sequence number
      u_int32_t ack_;       // tcp ack number

      // ToDo(Masa): 4 bit data field should be updated for little-endian
      u_int8_t x2_:4, offset_:4;

      u_int8_t flags_;      // flags
      u_int16_t window_;    // window
      u_int16_t chksum_;    // checksum
      u_int16_t urgptr_;    // urgent pointer
    } __attribute__((packed));

    static const u_int8_t FIN  = 0x01;
    static const u_int8_t SYN  = 0x02;
    static const u_int8_t RST  = 0x04;
    static const u_int8_t PUSH = 0x08;
    static const u_int8_t ACK  = 0x10;
    static const u_int8_t URG  = 0x20;
    static const u_int8_t ECE  = 0x40;
    static const u_int8_t CWR  = 0x80;

    ev_id EV_PKT_, EV_SYN_;
    param_id P_SRC_PORT_, P_DST_PORT_, P_FLAGS_, P_SEQ_, P_ACK_, P_DATA_, P_HDR_;
    dec_id D_TCP_SSN_;

  public:
    DEF_REPR_CLASS (VarFlags, FacFlags);

    explicit TcpDecoder (NetDec * nd) : Decoder (nd) {
      // Event name assign
      this->EV_PKT_ = nd->assign_event ("tcp.packet", "TCP Packet");
      this->EV_SYN_ = nd->assign_event ("tcp.syn", "TCP SYN Packet");

      // Parameter name assign
      this->P_SRC_PORT_ =
        nd->assign_param ("tcp.src_port", "TCP Source Port",
                          new FacNum ());
      this->P_DST_PORT_ =
        nd->assign_param ("tcp.dst_port", "TCP Destination Port",
                          new FacNum ());
      this->P_FLAGS_ =
        nd->assign_param ("tcp.flags", "TCP Flags", new FacFlags ());
      this->P_SEQ_ = nd->assign_param ("tcp.seq", "TCP Sequence Number");
      this->P_ACK_ = nd->assign_param ("tcp.ack", "TCP Acknowledge");
      this->P_HDR_ = nd->assign_param ("tcp.header", "TCP Header without option");
      this->P_DATA_ = nd->assign_param ("tcp.data", "TCP Data Segment");
    }
    void setup (NetDec * nd) {
      // nothing to do
      this->D_TCP_SSN_ = nd->lookup_dec_id("tcp_ssn");
    };

    static Decoder * New (NetDec * nd) { return new TcpDecoder (nd); }

    bool decode (Property *p) {
      auto hdr = reinterpret_cast <struct tcp_header *>
        (p->payload (sizeof (struct tcp_header)));

      if (hdr == NULL) {
        return false;
      }

      // set data to property
      p->set (this->P_SRC_PORT_, &(hdr->src_port_), sizeof (hdr->src_port_));
      p->set (this->P_DST_PORT_, &(hdr->dst_port_), sizeof (hdr->dst_port_));
      p->set (this->P_FLAGS_,    &(hdr->flags_),    sizeof (hdr->flags_));
      p->set (this->P_SEQ_,      &(hdr->seq_),      sizeof (hdr->seq_));
      p->set (this->P_ACK_,      &(hdr->ack_),      sizeof (hdr->ack_));
      p->set (this->P_HDR_,      hdr,               sizeof (struct tcp_header));

      // push event
      p->push_event (this->EV_PKT_);

      assert (sizeof (hdr->src_port_) == sizeof (hdr->dst_port_));
      p->set_port (&(hdr->src_port_), &(hdr->dst_port_),
                   sizeof (hdr->src_port_));
      p->calc_hash();

      uint8_t fsra_flag = (hdr->flags_ & (SYN | ACK | RST | FIN));
      if (fsra_flag == SYN) {
        p->push_event (this->EV_SYN_);
      }

      size_t opt_len = hdr->offset_ * 4 - sizeof(struct tcp_header);
      byte_t *opt = p->payload(opt_len);
      if (opt == NULL) {
        debug(0, "invalid option length (%zu) or not enough payload", opt_len);
        return false;
      }

      if (p->remain() > 0) {
        size_t data_len = p->remain();
        byte_t *data_seg = p->refer(data_len);
        p->set(this->P_DATA_, data_seg, data_len);
      }

      this->emit(this->D_TCP_SSN_, p);

      return true;
    }
  };

  bool TcpDecoder::VarFlags::repr (std::string *s) const {
    assert (s != NULL);
    u_int8_t flags = this->num <u_int8_t> ();
    s->append ((flags & FIN) > 0 ? "F" : "*");
    s->append ((flags & SYN) > 0 ? "S" : "*");
    s->append ((flags & RST) > 0 ? "R" : "*");
    s->append ((flags & PUSH) > 0 ? "P" : "*");
    s->append ((flags & ACK) > 0 ? "A" : "*");
    s->append ((flags & URG) > 0 ? "U" : "*");
    s->append ((flags & ECE) > 0 ? "E" : "*");
    s->append ((flags & CWR) > 0 ? "C" : "*");
    return true;
  }

  INIT_DECODER (tcp, TcpDecoder::New);
}  // namespace swarm
