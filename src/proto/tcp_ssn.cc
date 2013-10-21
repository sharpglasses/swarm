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
  class TcpSession {
  };

  class TcpSsnDecoder : public Decoder {
  private:
    ev_id EV_EST_;
    param_id P_SEG_;

  public:
    explicit TcpSsnDecoder (NetDec * nd) : Decoder (nd) {
      this->EV_EST_ = nd->assign_event ("tcp_ssn.established",
                                        "TCP session established");
      this->P_SEG_ = nd->assign_param ("tcp_ssn.segment", "TCP segment data");
    }
    void setup (NetDec * nd) {
      // nothing to do
    };

    static Decoder * New (NetDec * nd) { return new TcpSsnDecoder (nd); }

    bool decode (Property *p) {
      // set data to property
      // p->set (this->P_SRC_PORT_, &(hdr->src_port_), sizeof (hdr->src_port_));

      // push event
      // p->push_event (this->EV_PKT_);

      return true;
    }
  };

  INIT_DECODER (tcp_ssn, TcpSsnDecoder::New);
}  // namespace swarm
