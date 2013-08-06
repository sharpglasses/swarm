#include "decode.h"

namespace swarm {
  std::map <std::string, Decoder * (*)(NetDec *)> DecoderMap::protocol_decoder_map_;


  bool DecoderMap::reg_protocol_decoder (const std::string &name, 
                                         Decoder * (*New) (NetDec *)) {
    DecoderMap::protocol_decoder_map_.insert (std::make_pair (name, New));
    return true;
  } 

  Decoder::Decoder (NetDec *nd) : nd_(nd) {
  }
  Decoder::~Decoder () {
  }
}
