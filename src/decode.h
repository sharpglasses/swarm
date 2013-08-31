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


#ifndef SRC_DECODE_H__
#define SRC_DECODE_H__

#include <map>
#include <string>
#include <vector>

#include "./swarm.h"

namespace swarm {
  class DecoderMap {
  private:
    static std::map <std::string, Decoder * (*)(NetDec * nd)>
      protocol_decoder_map_;

  public:
    DecoderMap ();
    static bool reg_protocol_decoder (const std::string &name,
                                      Decoder * (*New) (NetDec * nd));
    static int build_decoder_vector (NetDec * nd,
                                     std::vector <Decoder *> *dec_vec,
                                     std::vector <std::string> *dec_name);
  };

#define INIT_DECODER(NAME, FUNC)                    \
  bool __is_protocol_decoder_##NAME##_enable =      \
    DecoderMap::reg_protocol_decoder (#NAME, FUNC)

}  // namespace swarm

#endif  // SRC_DECODE_H__
