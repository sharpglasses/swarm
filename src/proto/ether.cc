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

    ev_id EV_ETH_PKT_;
    param_id P_SRC_, P_DST_, P_PROTO_, P_HDR_;
    dec_id D_IPV4_;
    dec_id D_IPV6_;
    
  public:
    explicit EtherDecoder (NetDec * nd) : Decoder (nd) {
      this->EV_ETH_PKT_ = nd->assign_event ("ether.packet");
      this->P_SRC_   = nd->assign_param ("ether.src");
      this->P_DST_   = nd->assign_param ("ether.dst");
      this->P_PROTO_ = nd->assign_param ("ether.param");
      this->P_HDR_   = nd->assign_param ("ether.hdr");
    }
    void setup (NetDec * nd) {
      this->D_IPV4_ = nd->lookup_dec_id ("ipv4");
      this->D_IPV6_ = nd->lookup_dec_id ("ipv6");
    };

    static Decoder * New (NetDec * nd) { return new EtherDecoder (nd); }

    bool decode (Property *p) {
      auto eth_hdr = reinterpret_cast <struct ether_header *>
        (p->payload (sizeof (struct ether_header)));
      if (eth_hdr == NULL) {
        return false;
      }

      return false;
    }
  };

  INIT_DECODER (ether, EtherDecoder::New);
} // namespace swarm
