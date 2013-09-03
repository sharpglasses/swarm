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


#include <pcap.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>

#include "./swarm.h"
#include "./decode.h"
#include "./var.h"
#include "./debug.h"


namespace swarm {
  // -------------------------------------------------------
  // Handler
  Handler::Handler () {
  }
  Handler::~Handler () {
  }

  HandlerEntry::HandlerEntry (hdlr_id hid, ev_id ev, Handler * hdlr) :
    id_(hid), ev_(ev), hdlr_(hdlr) {
  }
  HandlerEntry::~HandlerEntry () {
  }
  Handler * HandlerEntry::hdlr () const {
    return this->hdlr_;
  }
  hdlr_id HandlerEntry::id () const {
    return this->id_;
  }
  ev_id HandlerEntry::ev () const {
    return this->ev_;
  }

  // -------------------------------------------------------
  // Param
  const std::string Param::errmsg_ = "(error)";

  Param::Param (VarFactory * fac) : idx_(0), fac_(fac) {
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
    Var * v = this->retain ();

    if (copy) {
      v->copy (data, len);
    } else {
      v->set (data, len);
    }
  }
  Var * Param::retain () {
    Var * v;
    if (this->idx_ >= this->var_set_.size ())  {
      v = (this->fac_) ? this->fac_->New () : new Var ();
      this->var_set_.push_back (v);
      this->idx_++;
      assert (this->idx_ == this->var_set_.size ());
    } else {
      v = this->var_set_[this->idx_];
      this->idx_++;
    }

    return v;
  }
  byte_t * Param::get (size_t *len, size_t idx) const {
    if (idx < this->idx_) {
      return this->var_set_[idx]->get (len);
    } else {
      return NULL;
    }
  }

  std::string Param::repr (size_t idx) const {
    std::string buf;
    return (this->repr (&buf, idx)) ? buf : Param::errmsg_;
  }
  bool Param::repr (std::string *s, size_t idx) const {
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->repr (s);
    } else {
      return false;
    }
  }

  int32_t Param::int32 (size_t idx) const {
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->num <int32_t> ();
    } else {
      return 0;
    }
  }
  u_int32_t Param::uint32 (size_t idx) const {
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->num <u_int32_t> ();
    } else {
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
    } else {
      return false;
    }
  }
  bool Param::hex (std::string *s, size_t idx) const {
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->hex (s);
    } else {
      return false;
    }
  }
  bool Param::ip4 (std::string *s, size_t idx) const {
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->ip4 (s);
    } else {
      return false;
    }
  }
  bool Param::ip6 (std::string *s, size_t idx) const {
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->ip6 (s);
    } else {
      return false;
    }
  }
  bool Param::mac (std::string *s, size_t idx) const {
    if (idx < this->idx_) {
      assert (idx < this->var_set_.size ());
      assert (this->var_set_[idx] != NULL);
      return this->var_set_[idx]->mac (s);
    } else {
      return false;
    }
  }

  // -------------------------------------------------------
  // ParamEntry
  ParamEntry::ParamEntry (param_id pid, const std::string name,
                          VarFactory * fac) :
    pid_(pid), name_(name), fac_(fac) {
    // ParamEntry has responsibility to manage fac (VarFactory)
  }
  ParamEntry::~ParamEntry () {
    delete this->fac_;
  }
  param_id ParamEntry::pid () const {
    return this->pid_;
  }
  const std::string& ParamEntry::name () const {
    return this->name_;
  }
  VarFactory * ParamEntry::fac () const {
    return this->fac_;
  }



  // -------------------------------------------------------
  // Property
  Property::Property (NetDec * nd) : nd_(nd), buf_(NULL), buf_len_(0) {
    this->nd_->build_param_vector (&(this->param_));
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

    for (size_t i = 0; i < this->param_.size (); i++) {
      this->param_[i]->init ();
    }

    this->ev_push_ptr_ = 0;
    this->ev_pop_ptr_ = 0;
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

    if (this->ptr_ + alloc_size <= this->cap_len_) {
      size_t p = this->ptr_;
      this->ptr_ += alloc_size;
      return &(this->buf_[p]);
    } else {
      return NULL;
    }
  }
  size_t Property::remain () const {
    if (this->ptr_ < this->cap_len_) {
      return (this->cap_len_ - this->ptr_);
    } else {
      return 0;
    }
  }

  Var * Property::retain (const std::string &param_name) {
    const param_id pid = this->nd_->lookup_param_id (param_name);
    if (pid == PARAM_NULL) {
      return false;
    } else {
      return this->retain (pid);
    }
  }
  Var * Property::retain (const param_id pid) {
    size_t idx = static_cast <size_t> (pid - PARAM_BASE);
    if (idx < this->param_.size ()) {
      Var * v = this->param_[idx]->retain ();
      return v;
    } else {
      return NULL;
    }
  }

  bool Property::set (const std::string &param_name, void * ptr, size_t len) {
    const param_id pid = this->nd_->lookup_param_id (param_name);
    if (pid == PARAM_NULL) {
      return false;
    } else {
      return this->set (pid, ptr, len);
    }
  }

  bool Property::set (const param_id pid, void * ptr, size_t len) {
    size_t idx = static_cast <size_t> (pid - PARAM_BASE);
    if (idx < this->param_.size () && ptr) {
      assert (idx < this->param_.size () && this->param_[idx] != NULL);
      this->param_[idx]->push (static_cast <byte_t*> (ptr), len);
      return true;
    } else {
      return false;
    }
  }
  bool Property::copy (const std::string &param_name, void * ptr, size_t len) {
    const param_id pid = this->nd_->lookup_param_id (param_name);
    if (pid == PARAM_NULL) {
      return false;
    } else {
      return this->copy (pid, ptr, len);
    }
  }
  bool Property::copy (const param_id pid, void * ptr, size_t len) {
    size_t idx = static_cast <size_t> (pid - PARAM_BASE);
    if (idx < this->param_.size () && ptr) {
      assert (idx < this->param_.size () && this->param_[idx] != NULL);
      this->param_[idx]->push (static_cast <byte_t*> (ptr), len, true);
      return true;
    } else {
      return false;
    }
  }

  ev_id Property::pop_event () {
    assert (this->ev_pop_ptr_ <= this->ev_push_ptr_);
    if (this->ev_pop_ptr_ < this->ev_push_ptr_) {
      const size_t i = this->ev_pop_ptr_++;
      return this->ev_queue_[i];
    } else {
      return EV_NULL;
    }
  }
  void Property::push_event (const ev_id eid) {
    if (this->ev_push_ptr_ >= this->ev_queue_.size ()) {
      // prevent frequet call of memory allocation
      this->ev_queue_.resize (this->ev_queue_.size () +
                              Property::EV_QUEUE_WIDTH);
    }
    this->ev_queue_[this->ev_push_ptr_] = eid;
    this->ev_push_ptr_++;
  }

  // -------------------------------------------------------
  // NetDec
  NetDec::NetDec () :
    base_eid_(EV_BASE),
    base_pid_(PARAM_BASE),
    base_hid_(HDLR_BASE),
    none_("") {
    int mod_count =
      DecoderMap::build_decoder_vector (this, &(this->dec_mod_),
                                        &(this->dec_name_));
    for (size_t i = 0; i < mod_count; i++) {
      this->fwd_dec_.insert (std::make_pair (this->dec_name_[i], i));
      this->rev_dec_.insert (std::make_pair (i, this->dec_name_[i]));
    }

    for (size_t n = 0; n < mod_count; n++) {
      this->dec_mod_[n]->setup (this);
    }

    this->dec_ether_ = this->lookup_dec_id ("ether");
    assert (this->dec_ether_ != DEC_NULL);
  }
  NetDec::~NetDec () {
    for (auto it = this->rev_event_.begin ();
         it != this->rev_event_.end (); it++) {
      size_t i = static_cast<size_t> (it->first - EV_BASE);
      delete this->event_handler_[i];
    }

    this->fwd_dec_.clear ();
    this->rev_dec_.clear ();
  }



  bool NetDec::input (const byte_t *data, const size_t cap_len,
                      const size_t data_len, const struct timeval &tv,
                      const int dlt) {
    // main process of NetDec
    if (dlt == DLT_EN10MB) {
      Property * prop = new Property (this);
      prop->init (data, cap_len, data_len, tv);
      this->decode (this->dec_ether_, prop);

      ev_id eid;
      while (EV_NULL != (eid = prop->pop_event ())) {
        assert (0 <= eid && eid < this->event_handler_.size ());
        auto hdlr_list = this->event_handler_[eid];
        if (hdlr_list) {
          for (auto it = hdlr_list->begin (); it != hdlr_list->end (); it++) {
            Handler * hdlr = (*it)->hdlr ();
            assert (hdlr != NULL);
            hdlr->recv (eid, *prop);
          }
        }
      }

      delete prop;
      return true;
    } else {
      return false;
    }
  }
  ev_id NetDec::lookup_event_id (const std::string &name) {
    auto it = this->fwd_event_.find (name);
    return (it != this->fwd_event_.end ()) ? it->second : EV_NULL;
  }

  std::string NetDec::lookup_event_name (ev_id eid) {
    auto it = this->rev_event_.find (eid);
    return (it != this->rev_event_.end ()) ? it->second : this->none_;
  }
  size_t NetDec::event_size () const {
    assert (this->base_eid_ >= 0);
    assert (this->base_eid_ == this->fwd_event_.size ());
    return this->fwd_event_.size ();
  }

  std::string NetDec::lookup_param_name (param_id pid) {
    auto it = this->rev_param_.find (pid);
    if (it != this->rev_param_.end ()) {
      return (it->second)->name ();
    } else {
      return this->none_;
    }
  }
  param_id NetDec::lookup_param_id (const std::string &name) {
    auto it = this->fwd_param_.find (name);
    return (it != this->fwd_param_.end ()) ? (it->second)->pid () : PARAM_NULL;
  }
  size_t NetDec::param_size () const {
    assert (this->base_pid_ >= 0);
    assert (this->base_pid_ == this->fwd_param_.size ());
    return this->fwd_param_.size ();
  }

  dec_id NetDec::lookup_dec_id (const std::string &name) {
    auto it = this->fwd_dec_.find (name);
    if (it != this->fwd_dec_.end ()) {
      return it->second;
    } else {
      return DEC_NULL;
    }
  }


  hdlr_id NetDec::set_handler (ev_id eid, Handler * hdlr) {
    const size_t idx = NetDec::eid2idx (eid);
    if (eid < EV_BASE || this->event_handler_.size () <= idx) {
      return HDLR_NULL;
    } else {
      hdlr_id hid = this->base_hid_++;
      HandlerEntry * ent = new HandlerEntry (hid, eid, hdlr);
      this->event_handler_[idx]->push_back (ent);
      auto p = std::make_pair (hid, ent);
      this->rev_hdlr_.insert (p);
      return hid;
    }
  }

  hdlr_id NetDec::set_handler (const std::string ev_name, Handler * hdlr) {
    auto it = this->fwd_event_.find (ev_name);
    if (it == this->fwd_event_.end ()) {
      return HDLR_NULL;
    } else {
      return this->set_handler (it->second, hdlr);
    }
  }

  Handler * NetDec::unset_handler (hdlr_id entry) {
    auto it = this->rev_hdlr_.find (entry);
    if (it == this->rev_hdlr_.end ()) {
      return NULL;
    } else {
      HandlerEntry * ent = it->second;
      this->rev_hdlr_.erase (it);
      size_t idx = NetDec::eid2idx (ent->ev ());
      auto dq = this->event_handler_[idx];
      for (auto dit = dq->begin (); dit != dq->end (); dit++) {
        if ((*dit)->id () == ent->id ()) {
          dq->erase (dit);
          break;
        }
      }
      Handler * hdlr = ent->hdlr ();
      delete ent;
      return hdlr;
    }
  }

  ev_id NetDec::assign_event (const std::string &name) {
    if (this->fwd_event_.end () != this->fwd_event_.find (name)) {
      return EV_NULL;
    } else {
      const ev_id eid = this->base_eid_;
      this->fwd_event_.insert (std::make_pair (name, eid));
      this->rev_event_.insert (std::make_pair (eid, name));

      const size_t idx = NetDec::eid2idx (eid);
      if (this->event_handler_.size () <= idx) {
        this->event_handler_.resize (idx + 1);
      }
      this->event_handler_[idx] = new std::deque <HandlerEntry *> ();

      this->base_eid_++;
      return eid;
    }
  }
  param_id NetDec::assign_param (const std::string &name, VarFactory * fac) {
    if (this->fwd_param_.end () != this->fwd_param_.find (name)) {
      return PARAM_NULL;
    } else {
      const ev_id pid = this->base_pid_;

      ParamEntry * ent = new ParamEntry (pid, name, fac);
      this->fwd_param_.insert (std::make_pair (name, ent));
      this->rev_param_.insert (std::make_pair (pid,  ent));
      this->base_pid_++;
      return pid;
    }
  }

  void NetDec::decode (dec_id dec, Property *p) {
    assert (0 <= dec && dec < this->dec_mod_.size ());
    this->dec_mod_[dec]->decode (p);
  }

  void NetDec::build_param_vector (std::vector <Param *> * prm_vec_) {
    prm_vec_->resize (this->param_size ());

    for (auto it = this->fwd_param_.begin ();
         it != this->fwd_param_.end (); it++) {
      ParamEntry * ent = it->second;
      size_t idx = Property::pid2idx (ent->pid ());
      assert (idx < prm_vec_->size ());
      (*prm_vec_)[idx] = new Param (ent->fac ());
    }
  }

}  // namespace swarm

