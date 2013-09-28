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


#include <arpa/inet.h>
#include "./property.h"
#include "./var.h"

namespace swarm {
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
  ParamEntry::ParamEntry (param_id pid, const std::string &name,
                          const std::string &desc, VarFactory * fac) :
    pid_(pid), name_(name), desc_(desc), fac_(fac) {
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
  const std::string& ParamEntry::desc () const {
    return this->desc_;
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

    this->addr_len_ = 0;
    this->port_len_ = 0;
    this->proto_ = 0;
    this->hash_value_ = 0;
  }
  Param * Property::param (const std::string &key) const {
    const param_id pid = this->nd_->lookup_param_id (key);
    return (pid != PARAM_NULL) ? this->param (pid) : NULL;
  }
  Param * Property::param (const param_id pid) const {
    size_t idx = Property::pid2idx (pid);
    return (idx < this->param_.size ()) ? this->param_[idx] : NULL;
  }
  u_int64_t Property::get_5tuple_hash () const {
    return this->hash_value_;
  }
  size_t Property::len () const {
    return this->data_len_;
  }
  size_t Property::cap_len () const {
    return this->cap_len_;
  }
  void Property::tv (struct timeval *tv) const {
    tv->tv_sec = this->tv_sec_;
    tv->tv_usec = this->tv_usec_;
  }
  double Property::ts () const {
    double ts = static_cast <double> (this->tv_sec_) +
      static_cast <double> (this->tv_usec_) / 1000000;
    return ts;
  }
  byte_t * Property::refer (size_t alloc_size) {
    // Swarm supports maximum 16MB for one packet lengtsh
    assert (alloc_size < 0xfffffff);
    assert (this->ptr_ < 0xfffffff);

    if (this->ptr_ + alloc_size <= this->cap_len_) {
      size_t p = this->ptr_;
      return &(this->buf_[p]);
    } else {
      return NULL;
    }
  }

  byte_t * Property::payload (size_t alloc_size) {
    // Swarm supports maximum 16MB for one packet lengtsh
    byte_t * p = this->refer (alloc_size);
    if (p) {
      this->ptr_ += alloc_size;
    }
    return p;
  }
  size_t Property::remain () const {
    if (this->ptr_ < this->cap_len_) {
      return (this->cap_len_ - this->ptr_);
    } else {
      return 0;
    }
  }

  void Property::addr2str (void * addr, size_t len, std::string *s) {
    char buf[32];
    if (len == 4) {
      ::inet_ntop (AF_INET, addr, buf, sizeof (buf));
      s->assign (buf);
    } else if (len == 16) {
      ::inet_ntop (AF_INET6, addr, buf, sizeof (buf));
      s->assign (buf);
    } else {
      s->assign ("unsupported address");
    }
  }
  std::string Property::src_addr () const {
    std::string buf;
    addr2str (this->src_addr_, this->addr_len_, &buf);
    return buf;
  }
  std::string Property::dst_addr () const {
    std::string buf;
    addr2str (this->dst_addr_, this->addr_len_, &buf);
    return buf;
  }
  void *Property::src_addr (size_t *len) const {
    *len = this->addr_len_;
    return this->src_addr_;
  }
  void *Property::dst_addr (size_t *len) const {
    *len = this->addr_len_;
    return this->dst_addr_;
  }

  int Property::src_port () const {
    if (this->port_len_ == 2) {
      u_int16_t * p = static_cast<u_int16_t*> (this->src_port_);
      return static_cast<int> (ntohs (*p));
    } else {
      // unsupported
      return 0;
    }
  }
  int Property::dst_port () const {
    if (this->port_len_ == 2) {
      u_int16_t * p = static_cast<u_int16_t*> (this->dst_port_);
      return static_cast<int> (ntohs (*p));
    } else {
      // unsupported
      return 0;
    }
  }
  std::string Property::proto () const {
    static const u_int8_t PROTO_ICMP  = 1;
    static const u_int8_t PROTO_TCP   = 6;
    static const u_int8_t PROTO_UDP   = 17;
    static const u_int8_t PROTO_IPV6  = 41;
    static const u_int8_t PROTO_ICMP6 = 58;

    std::string s;
    switch (this->proto_) {
    case PROTO_ICMP:  s = "ICMP";    break;
    case PROTO_TCP:   s = "TCP";     break;
    case PROTO_UDP:   s = "UDP";     break;
    case PROTO_IPV6:  s = "IPv6";    break;
    case PROTO_ICMP6: s = "ICMPv6";  break;
    default:          s = "unknown"; break;
    }

    return s;
  }

  Var * Property::retain (const std::string &param_name) {
    const param_id pid = this->nd_->lookup_param_id (param_name);
    if (pid == PARAM_NULL) {
      return NULL;
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

  void Property::calc_hash () {
    void *la, *ra;
    void *lp, *rp;
    if (::memcmp (this->src_addr_, this->dst_addr_, this->addr_len_) > 0) {
      la = this->src_addr_;
      ra = this->dst_addr_;
      lp = this->src_port_;
      rp = this->dst_port_;
    } else {
      ra = this->src_addr_;
      la = this->dst_addr_;
      rp = this->src_port_;
      lp = this->dst_port_;
    }

    u_int64_t h = 1125899906842597;
    u_int32_t * l32 = static_cast <u_int32_t *> (la);
    u_int32_t * r32 = static_cast <u_int32_t *> (ra);

#define __HASH(X)  (X + (h << 6) + (h << 16) - h)

    if (this->addr_len_ == 4) {
      // for IPv4
      h = __HASH (*l32);
      h = __HASH (*r32);
    } else if (this->addr_len_ == 16) {
      // for IPv6 + TCP/UDP
      for (size_t i = 0; i < 4; i++) {
        // expected to expaned by optimization
        h = __HASH (l32[i]);
        h = __HASH (r32[i]);
      }
    } else {
      // in this moment, not support other IP version
      assert (this->addr_len_ == 0);
    }

    h = __HASH (this->proto_);

    if (this->port_len_ == 2) {
      // for TCP or UDP
      u_int16_t * l16 = static_cast <u_int16_t *> (lp);
      u_int16_t * r16 = static_cast <u_int16_t *> (rp);
      h = __HASH (*l16);
      h = __HASH (*r16);
    } else {
      // in this moment, not support other protocol than TCP, UDP
      assert (this->port_len_ == 0);
    }

    this->hash_value_ = h;
  }
  void Property::set_addr (void *src_addr, void *dst_addr, u_int8_t proto,
                           size_t addr_len) {
    this->addr_len_ = addr_len;
    this->src_addr_ = src_addr;
    this->dst_addr_ = dst_addr;
    this->proto_ = proto;
  }
  void Property::set_port (void *src_port, void *dst_port, size_t port_len) {
    this->port_len_ = port_len;
    this->src_port_ = src_port;
    this->dst_port_ = dst_port;
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

}  // namespace swarm
