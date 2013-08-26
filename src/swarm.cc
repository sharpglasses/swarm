#include "swarm.h"
#include "decode.h"

#include <pcap.h>
#include <stdlib.h>

namespace swarm {
  // -------------------------------------------------------
  // Handler
  Handler::Handler () {
  }
  Handler::~Handler () {
  }

  // -------------------------------------------------------
  // Param
  const std::string Param::errmsg_ = "(error)";

  Param::Param () : len_(0) {
  }
  Param::~Param () {
  }
  void Param::init () {
    this->len_ = 0;
  }
  size_t Param::size () const {
    return this->len_;
  }
  void Param::push (byte_t *data, size_t len, bool copy) {
  }
  byte_t * Param::get (size_t *len, size_t idx) {
    return NULL;
  }

  int32_t Param::int32 (size_t idx) { return 0; }
  u_int32_t Param::uint32 (size_t idx) { return 0; }
  int64_t Param::int64 (size_t idx) { return 0; }
  u_int64_t Param::uint64 (size_t idx) { return 0; }
  std::string Param::str (size_t idx) {
    return Param::errmsg_;
  }
  std::string Param::hex (size_t idx) {
    return Param::errmsg_;
  }
  std::string Param::ip4 (size_t idx) {
    return Param::errmsg_;
  }
  std::string Param::ip6 (size_t idx) {
    return Param::errmsg_;
  }
  std::string Param::mac (size_t idx) {
    return Param::errmsg_;
  }

  bool Param::str (std::string *s, size_t idx) { return false; }
  bool Param::hex (std::string *s, size_t idx) { return false; }
  bool Param::ip4 (std::string *s, size_t idx) { return false; }
  bool Param::ip6 (std::string *s, size_t idx) { return false; }
  bool Param::mac (std::string *s, size_t idx) { return false; }    

  // -------------------------------------------------------
  // Decoder
  void Decoder::emit (dec_id dec, Property *p) {
  }

  // -------------------------------------------------------
  // Property
  Property::Property (NetDec * nd) : nd_(nd), buf_(NULL), buf_len_(0) {
  }
  Property::~Property () {
    if (this->buf_) {
      free (this->buf_); 
    }
  }
  void Property::init  (const byte_t *data, const size_t cap_len, 
                        const size_t data_len, const struct timeval &tv) {
    if (this->buf_len_ < cap_len) {
      this->buf_len_ = cap_len;
      this->buf_ = static_cast <byte_t *>
        (::realloc (static_cast <void*> (this->buf_), this->buf_len_));
    }

    this->tv_sec_ = 0;
    this->tv_usec_ = 0;
    this->data_len_ = 0;
    this->cap_len_ = 0;
    this->ptr_ = 0;
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
    int mod_count = 
      DecoderMap::build_decoder_vector (this, &(this->dec_mod_), &(this->dec_name_)); 
    for (int i = 0; i < mod_count; i++) {
      this->dict_dec_.insert (std::make_pair (this->dec_name_[i], i));
    } 

    this->dec_ether_ = this->lookup_dec_id ("ether");    
  }
  NetDec::~NetDec () {
    
  }



  bool NetDec::input (const byte_t *data, const size_t cap_len, 
                      const size_t data_len, 
                      const struct timeval &tv, const int dlt) {    
    if (dlt == DLT_EN10MB) {
      return false;
    }
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
  dec_id NetDec::lookup_dec_id (const std::string &name) {
    return DEC_NULL;
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

