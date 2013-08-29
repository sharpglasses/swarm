#include "swarm.h"
#include "decode.h"
#include "var.h"
#include "debug.h"

#include <pcap.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>


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

  Param::Param () : idx_(0) {
  }
  Param::~Param () {
  }
  void Param::init () {
    this->idx_ = 0;
  }
  size_t Param::size () const {
    return this->idx_;
  }
  void Param::push (byte_t *data, size_t len, bool copy) {
    Var * v;
    if (this->idx_ >= this->var_set_.size ())  {
      v = new Var ();
      this->var_set_.push_back (v);
      this->idx_++;
      assert (this->idx_ == this->var_set_.size ());
    }
    else {
      v = this->var_set_[this->idx_];
      this->idx_++;
    }

    if (copy) {
      v->copy (data, len);
    }
    else {
      v->set (data, len);
    }
  }
  byte_t * Param::get (size_t *len, size_t idx) const {
    if (idx < this->idx_) {
      return this->var_set_[idx]->get (len);
    }
    else {
      return NULL;
    }
  }

  int32_t Param::int32 (size_t idx) const { 
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->num <int32_t> ();
    }
    else {
      return 0;
    }
  }
  u_int32_t Param::uint32 (size_t idx) const { 
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->num <u_int32_t> ();
    }
    else {
      return 0;
    }
  }


  std::string Param::str (size_t idx) const {
    std::string buf;
    return (this->str (&buf, idx)) ? buf : Param::errmsg_;
  }
  std::string Param::hex (size_t idx) const {
    std::string buf;
    return (this->hex (&buf, idx)) ? buf : Param::errmsg_;
  }
  std::string Param::ip4 (size_t idx) const {
    std::string buf;
    return (this->ip4 (&buf, idx)) ? buf : Param::errmsg_;
  }
  std::string Param::ip6 (size_t idx) const {
    std::string buf;
    return (this->ip6 (&buf, idx)) ? buf : Param::errmsg_;
  }
  std::string Param::mac (size_t idx) const {
    std::string buf;
    return (this->mac (&buf, idx)) ? buf : Param::errmsg_;
  }

  bool Param::str (std::string *s, size_t idx) const { 
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->str (s);
    }
    else {
      return false;
    }
  }
  bool Param::hex (std::string *s, size_t idx) const { 
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->hex (s);
    }
    else {
      return false;
    }
  }
  bool Param::ip4 (std::string *s, size_t idx) const { 
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->ip4 (s);
    }
    else {
      return false;
    }
  }
  bool Param::ip6 (std::string *s, size_t idx) const { 
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->ip6 (s);
    }
    else {
      return false;
    }
  }
  bool Param::mac (std::string *s, size_t idx) const {
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->mac (s);
    }
    else {
      return false;
    }
  }

  // -------------------------------------------------------
  // Decoder
  void Decoder::emit (dec_id dec, Property *p) {
  }

  // -------------------------------------------------------
  // Property
  Property::Property (NetDec * nd) : nd_(nd), buf_(NULL), buf_len_(0) {
    this->param_.resize (nd->param_size ());
    for (size_t i = 0; i < this->param_.size (); i++) {
      this->param_[i] = new Param ();
    }
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

    this->tv_sec_   = tv.tv_sec;
    this->tv_usec_  = tv.tv_usec;
    this->data_len_ = data_len;
    this->cap_len_  = cap_len;
    this->ptr_      = 0;

    assert (this->buf_len_ >= cap_len);
    ::memcpy (this->buf_, data, cap_len);
  }
  Param * Property::param (const std::string &key) const {
    const param_id pid = this->nd_->lookup_param_id (key);
    return (pid != PARAM_NULL) ? this->param (pid) : NULL;
  }
  Param * Property::param (const param_id pid) const {
    size_t idx = Property::pid2idx (pid);
    return (idx < this->param_.size ()) ? this->param_[idx] : NULL;
  }
  byte_t * Property::payload (size_t alloc_size) {
    // Swarm supports maximum 16MB for one packet lengtsh
    assert (alloc_size < 0xfffffff);
    assert (this->ptr_ < 0xfffffff);

    if (this->ptr_ + alloc_size < this->cap_len_) {
      size_t p = this->ptr_;
      this->ptr_ += alloc_size;
      return &(this->buf_[p]);
    }
    else {
      return NULL;
    }
  }

  bool Property::set (const std::string &param_name, void * ptr, size_t len) { 
    const param_id pid = this->nd_->lookup_param_id (param_name);
    if (pid == PARAM_NULL) {
      return false;
    }
    else {
      return this->set (pid, ptr, len);
    }
  }

  bool Property::set (const param_id pid, void * ptr, size_t len) { 
    size_t idx = static_cast <size_t> (pid - PARAM_BASE);
    if (idx < this->param_.size ()) {
      assert (idx < this->param_.size () && this->param_[idx] != NULL);
      this->param_[idx]->push (static_cast <byte_t*> (ptr), len);
      return true;
    }
    else {
      return false;
    }
  }
  bool Property::copy (const std::string &param_name, void * ptr, size_t len) {
    const param_id pid = this->nd_->lookup_param_id (param_name);
    if (pid == PARAM_NULL) {
      return false;
    }
    else {
      return this->copy (pid, ptr, len);
    }
  }
  bool Property::copy (const param_id pid, void * ptr, size_t len) { 
    size_t idx = static_cast <size_t> (pid - PARAM_BASE);
    if (idx < this->param_.size ()) {
      assert (idx < this->param_.size () && this->param_[idx] != NULL);
      this->param_[idx]->push (static_cast <byte_t*> (ptr), len, true);
      return true;
    }
    else {
      return false;
    }
  }

  // -------------------------------------------------------
  //NetDec
  NetDec::NetDec () : 
    base_eid_(0),
    base_pid_(0),
    none_("") {
    int mod_count = 
      DecoderMap::build_decoder_vector (this, &(this->dec_mod_), &(this->dec_name_)); 
    for (int i = 0; i < mod_count; i++) {
      this->fwd_dec_.insert (std::make_pair (this->dec_name_[i], i));
      this->rev_dec_.insert (std::make_pair (i, this->dec_name_[i]));
    } 

    this->dec_ether_ = this->lookup_dec_id ("ether");    
  }
  NetDec::~NetDec () {
    
  }



  bool NetDec::input (const byte_t *data, const size_t cap_len, 
                      const size_t data_len, const struct timeval &tv, const int dlt) { 
    if (dlt == DLT_EN10MB) {
      return false;
    }
    return false;
  }
  ev_id NetDec::lookup_event_id (const std::string &name) {
    return EV_NULL;
  }

  std::string NetDec::lookup_event_name (ev_id eid) {
    return this->none_;
  }
  size_t NetDec::event_size () const {
    assert (this->base_eid_ >= 0);
    assert (this->base_eid_ == this->fwd_event_.size ());
    return this->fwd_event_.size ();
  }

  std::string NetDec::lookup_param_name (param_id pid) {
    return this->none_;
  }
  param_id NetDec::lookup_param_id (const std::string &name) {
    auto it = this->fwd_param_.find (name);    
    return (it != this->fwd_param_.end ()) ? it->second : PARAM_NULL;
  }
  size_t NetDec::param_size () const {
    assert (this->base_pid_ >= 0);
    assert (this->base_pid_ == this->fwd_param_.size ());
    return this->fwd_param_.size ();
  }

  dec_id NetDec::lookup_dec_id (const std::string &name) {
    return this->fwd_dec_.size ();
  }


  hdlr_id NetDec::set_handler (ev_id eid, Handler * hdlr) {
    return HDLR_NULL;
  }
  bool NetDec::unset_handler (hdlr_id entry) {
    return false;
  }

  ev_id NetDec::assign_event (const std::string &name) {
    if (this->fwd_event_.end () != this->fwd_event_.find (name)) {
      return EV_NULL;
    }
    else {
      const ev_id eid = this->base_eid_;
      this->fwd_event_.insert (std::make_pair (name, eid));
      this->rev_event_.insert (std::make_pair (eid, name));
      this->base_eid_++;
      return eid;
    }
  }
  param_id NetDec::assign_param (const std::string &name) {
    if (this->fwd_param_.end () != this->fwd_param_.find (name)) {
      return PARAM_NULL;
    }
    else {
      const ev_id pid = this->base_pid_;
      this->fwd_param_.insert (std::make_pair (name, pid));
      this->rev_param_.insert (std::make_pair (pid, name));
      this->base_pid_++;
      return pid;
    }
  }


}

