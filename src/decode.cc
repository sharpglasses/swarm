#include "decode.h"

namespace swarm {
  std::map <std::string, Decoder * (*)(NetDec *)> DecoderMap::protocol_decoder_map_;


  bool DecoderMap::reg_protocol_decoder (const std::string &name, 
                                         Decoder * (*New) (NetDec *)) {
    DecoderMap::protocol_decoder_map_.insert (std::make_pair (name, New));
    return true;
  } 

  int DecoderMap::build_decoder_vector (NetDec * nd, std::vector <Decoder *> *dec_vec, 
                                         std::vector <std::string> *dec_name) {
    // TODO: need to check contents of dec_vec, dec_name
    const size_t len = DecoderMap::protocol_decoder_map_.size ();
    size_t i = 0;
    dec_vec->resize (len);
    dec_name->resize (len);

    for (auto it = DecoderMap::protocol_decoder_map_.begin ();
         it != DecoderMap::protocol_decoder_map_.end (); it++, i++) {
      (*dec_name)[i] = it->first;
      (*dec_vec)[i] = (it->second) (nd);
    }

    return i;
  }

  Decoder::Decoder (NetDec *nd) : nd_(nd) {
  }
  Decoder::~Decoder () {
  }
}
