#include "swarm.h"
#include "decode.h"

namespace swarm {
  // -------------------------------------------------------
  // Handler
  Handler::Handler () {
  }
  Handler::~Handler () {
  }

  // -------------------------------------------------------
  // Param
  size_t Param::size () const {
    return 0;
  }
  byte_t * Param::get (size_t idx, size_t *len) const {
    return NULL;
  }
  bool Param::str (size_t idx, std::string *s) const {
    return false;
  }


  // -------------------------------------------------------
  // Decoder
  void Decoder::emit (Property *p) {
  }

  // -------------------------------------------------------
  // Property
  Property::Property (NetDec * nd) : nd_(nd) {
  }

  void Property::init () {
  }
  Param * Property::param (const std::string &key) const {
    return NULL;
  }
  Param * Property::param (const param_id pid) const {
    return NULL;
  }
  byte_t * Property::payload (size_t alloc_size) {
    return NULL;
  }

  // -------------------------------------------------------
  //NetDec
  NetDec::NetDec () : none_("") {
    
  }
  NetDec::~NetDec () {
  }

  bool NetDec::input (const byte_t *data, const size_t cap_len, 
                      const size_t data_len, 
                      const struct timeval &tv) {
    return false;
  }
  ev_id NetDec::lookup_ev_id (const std::string &name) {
    return EV_NULL;
  }

  std::string NetDec::lookup_ev_name (ev_id eid) {
    return this->none_;
  }
  std::string NetDec::lookup_param_name (param_id pid) {
    return this->none_;
  }
  param_id NetDec::lookup_param_id (const std::string &name) {
    return PARAM_NULL;
  }

  hdlr_id NetDec::set_handler (ev_id eid, Handler * hdlr) {
    return HDLR_NULL;
  }
  bool NetDec::unset_handler (hdlr_id entry) {
    return false;
  }

  ev_id NetDec::assign_event (const std::string &name) {
    return EV_NULL;
  }
  param_id NetDec::assign_param (const std::string &name) {
    return PARAM_NULL;
  }


}

