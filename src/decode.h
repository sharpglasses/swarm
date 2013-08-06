#ifndef __SWARM_DECODE_H__
#define __SWARM_DECODE_H__

#include "swarm.h"
#include <map>

namespace swarm {
  class DecoderMap {
  private:
    static std::map <std::string, Decoder * (*)(NetDec *)> protocol_decoder_map_;

  public:
    static bool reg_protocol_decoder (const std::string &name, Decoder * (*New) (NetDec *));
    void build_decoder_vector (std::vector <Decoder *> *dec_vec, 
                               std::vector <std::string> *dec_name);
  };

#define INIT_DECODER(NAME,FUNC)                                         \
  bool __is_protocol_decoder_##NAME##_enable = DecoderMap::reg_protocol_decoder (#NAME, FUNC)

}

#endif
