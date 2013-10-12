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

#include <string.h>
#include "./netdec.h"
#include "./property.h"
#include "./decode.h"
#include "./timer.h"

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
  // NetDec
  NetDec::NetDec () :
    base_eid_(EV_BASE),
    base_pid_(PARAM_BASE),
    base_hid_(HDLR_BASE),
    none_(""),
    recv_len_(0),
    cap_len_(0),
    recv_pkt_(0),
    timer_(new Timer ()) {
    this->init_ts_.tv_sec = 0;;
    this->init_ts_.tv_nsec = 0;;
    this->last_ts_.tv_sec = 0;;
    this->last_ts_.tv_nsec = 0;;

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

    this->dec_default_ = this->lookup_dec_id ("ether");
    assert (this->dec_default_ != DEC_NULL);
    this->prop_ = new Property (this);
  }
  NetDec::~NetDec () {
    for (auto it = this->rev_event_.begin ();
         it != this->rev_event_.end (); it++) {
      size_t i = static_cast<size_t> (it->first - EV_BASE);
      delete this->event_handler_[i];
    }

    this->fwd_dec_.clear ();
    this->rev_dec_.clear ();
    delete this->timer_;
  }



  bool NetDec::set_default_decoder (const std::string &dec_name) {
    dec_id d_id = this->lookup_dec_id (dec_name);
    if (d_id != DEC_NULL) {
      this->dec_default_ = d_id;
      return true;
    } else {
      return false;
    }
  }
  bool NetDec::input (const byte_t *data, const size_t len,
                      const struct timeval &tv, const size_t cap_len) {
    // main process of NetDec
    Property * prop = this->prop_;
    // If cap_len == 0, actual captured length is same with real packet length
    size_t c_len = (cap_len == 0) ? len : cap_len;

    // update stat information
    if (this->init_ts_.tv_sec == 0) {
      this->init_ts_.tv_sec = tv.tv_sec;
      this->init_ts_.tv_nsec = tv.tv_usec * 1000;
    }

    this->recv_pkt_ += 1;
    this->recv_len_ += len;
    this->cap_len_ += c_len;
    this->last_ts_.tv_sec = tv.tv_sec;
    this->last_ts_.tv_nsec = tv.tv_usec * 1000;

    // Initialize property with packet data
    // NOTE: memory of data must be secured in this function because of
    //       zero-copy impolementation.
    prop->init (data, c_len, len, tv);

    // emit to decoder
    this->decode (this->dec_default_, prop);

    // calculate hash value of 5 tuple
    prop->calc_hash ();

    // execute callback function of handler
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

    // handle timer
    this->timer_->ticktock (tv);

    return true;
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

  task_id NetDec::set_onetime_timer (Task *task, int delay_msec) {
    return this->timer_->install_task (task, Timer::ONCE, delay_msec);
  }
  task_id NetDec::set_repeat_timer (Task *task, int interval_msec) {
    return this->timer_->install_task (task, Timer::REPEAT, interval_msec);
  }
  bool NetDec::unset_timer (task_id id) {
    return this->timer_->remove_task (id);
  }

  uint64_t NetDec::recv_len () const {
    return this->recv_len_;
  }
  uint64_t NetDec::cap_len () const {
    return this->cap_len_;
  }
  uint64_t NetDec::recv_pkt () const {
    return this->recv_pkt_;
  }
  void NetDec::init_ts (struct timespec *ts) const {
    memcpy (ts, &(this->init_ts_), sizeof (struct timespec));
  }
  void NetDec::last_ts (struct timespec *ts) const {
    memcpy (ts, &(this->init_ts_), sizeof (struct timespec));
  }
  double NetDec::init_ts () const {
    return static_cast<double> (this->init_ts_.tv_sec) +
      static_cast<double> (this->init_ts_.tv_nsec) / (1000 * 1000 * 1000);
  }
  double NetDec::last_ts () const {
    return static_cast<double> (this->last_ts_.tv_sec) +
      static_cast<double> (this->last_ts_.tv_nsec) / (1000 * 1000 * 1000);
  }

  const std::string &NetDec::errmsg () const {
    return this->errmsg_;
  }


  ev_id NetDec::assign_event (const std::string &name,
                              const std::string &desc) {
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
  param_id NetDec::assign_param (const std::string &name,
                                 const std::string &desc, VarFactory * fac) {
    if (this->fwd_param_.end () != this->fwd_param_.find (name)) {
      return PARAM_NULL;
    } else {
      const ev_id pid = this->base_pid_;

      ParamEntry * ent = new ParamEntry (pid, name, desc, fac);
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
