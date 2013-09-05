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

#ifndef SRC_SWARM_H__
#define SRC_SWARM_H__

#include <assert.h>
#include <sys/types.h>
#include <string>
#include <map>
#include <vector>
#include <deque>

namespace swarm {
  typedef u_int8_t  byte_t;  // 1 byte data type
  typedef int64_t    ev_id;  // Event ID
  typedef int64_t param_id;  // Parameter ID
  typedef int64_t  hdlr_id;  // Handler Entry ID
  typedef int       dec_id;  // Decoder ID

  const ev_id    EV_NULL = -1;
  const ev_id    EV_BASE =  0;
  const hdlr_id  HDLR_BASE =  0;
  const hdlr_id  HDLR_NULL = -1;
  const param_id PARAM_NULL = -1;
  const param_id PARAM_BASE =  0;
  const dec_id   DEC_NULL = -1;

  class NetDec;
  class Decoder;  // defined in decode.h
  class Var;  // defined in var.h
  class VarFactory;  // defined in var.h

  class Param {
  private:
    std::vector <Var *> var_set_;
    size_t idx_;
    VarFactory * fac_;

  public:
    static const std::string errmsg_;

    explicit Param (VarFactory *fac = NULL);
    ~Param ();
    void init ();

    size_t size () const;
    void push (byte_t *data, size_t len, bool copy = false);
    Var * retain ();
    byte_t * get (size_t *len = NULL, size_t idx = 0) const;

    std::string repr (size_t idx = 0) const;
    bool repr (std::string *s, size_t idx) const;

    int32_t int32 (size_t idx = 0) const;
    u_int32_t uint32 (size_t idx = 0) const;

    std::string str (size_t idx = 0) const;
    std::string hex (size_t idx = 0) const;
    std::string ip4 (size_t idx = 0) const;
    std::string ip6 (size_t idx = 0) const;
    std::string mac (size_t idx = 0) const;
    bool str (std::string *s, size_t idx) const;
    bool hex (std::string *s, size_t idx) const;
    bool ip4 (std::string *s, size_t idx) const;
    bool ip6 (std::string *s, size_t idx) const;
    bool mac (std::string *s, size_t idx) const;
  };

  class ParamEntry {
  private:
    param_id pid_;
    std::string name_;
    VarFactory * fac_;

  public:
    ParamEntry (param_id pid, const std::string name, VarFactory * fac);
    ~ParamEntry ();
    param_id pid () const;
    const std::string& name () const;
    VarFactory * fac () const;
  };

  class Property {
  private:
    NetDec * nd_;
    time_t tv_sec_;
    time_t tv_usec_;

    // buffer for payload management
    byte_t *buf_;
    size_t buf_len_;
    size_t data_len_;
    size_t cap_len_;
    size_t ptr_;

    // Parameter management
    std::vector <Param *> param_;

    // Event management
    std::vector <ev_id> ev_queue_;
    size_t ev_pop_ptr_;
    size_t ev_push_ptr_;
    const size_t EV_QUEUE_WIDTH = 128;


    u_int8_t proto_;
    size_t addr_len_;
    void *src_addr_, *dst_addr_;
    size_t port_len_;
    void *src_port_, *dst_port_;

    u_int64_t hash_value_;

  public:
    explicit Property (NetDec * nd);
    ~Property ();
    void init (const byte_t *data, const size_t cap_len,
               const size_t data_len, const struct timeval &tv);
    Var * retain (const std::string &param_name);
    Var * retain (const param_id pid);
    bool set (const std::string &param_name, void * ptr, size_t len);
    bool set (const param_id pid, void * ptr, size_t len);
    bool copy (const std::string &param_name, void * ptr, size_t len);
    bool copy (const param_id pid, void * ptr, size_t len);

    void set_addr (void *src_addr, void *dst_addr, u_int8_t proto,
                   size_t addr_len);
    void set_port (void *src_port, void *dst_port, size_t port_len);
    void calc_hash ();

    Param * param (const std::string &key) const;
    Param * param (const param_id pid) const;
    u_int64_t get_5tuple_hash () const;

    byte_t * payload (size_t alloc_size);
    size_t remain () const;

    ev_id pop_event ();
    void push_event (const ev_id eid);

    inline static size_t pid2idx (param_id pid) {
      return static_cast <size_t> (pid - PARAM_BASE);
    }
  };

  class Handler {
  public:
    Handler ();
    virtual ~Handler ();
    virtual void recv (ev_id eid, const Property &p) = 0;
  };

  class HandlerEntry {
  private:
    hdlr_id id_;
    ev_id ev_;
    Handler * hdlr_;

  public:
    HandlerEntry (hdlr_id hid, ev_id eid, Handler * hdlr_);
    ~HandlerEntry ();
    Handler * hdlr () const;
    hdlr_id id () const;
    ev_id ev () const;
  };



  class NetDec {
  private:
    std::map <std::string, ev_id> fwd_event_;
    std::map <ev_id, std::string> rev_event_;
    std::map <std::string, ParamEntry *> fwd_param_;
    std::map <param_id, ParamEntry *> rev_param_;
    std::map <std::string, dec_id> fwd_dec_;
    std::map <dec_id, std::string> rev_dec_;
    std::map <hdlr_id, HandlerEntry *> rev_hdlr_;
    ev_id base_eid_;
    param_id base_pid_;
    hdlr_id base_hid_;

    const std::string none_;
    std::vector <Decoder *> dec_mod_;
    std::vector <std::string> dec_name_;

    std::vector <std::deque <HandlerEntry *> * > event_handler_;
    dec_id dec_ether_;
    Property * prop_;

    inline static size_t eid2idx (const ev_id eid) {
      return static_cast <size_t> (eid - EV_BASE);
    }

  public:
    NetDec ();
    ~NetDec ();

    bool input (const byte_t *data, const size_t cap_len,
                const size_t data_len, const struct timeval &tv, int dlt);

    // Event
    ev_id lookup_event_id (const std::string &name);
    std::string lookup_event_name (ev_id eid);
    size_t event_size () const;

    // Parameter
    param_id lookup_param_id (const std::string &name);
    std::string lookup_param_name (param_id pid);
    size_t param_size () const;

    // Decoder
    dec_id lookup_dec_id (const std::string &name);

    // Handler
    hdlr_id set_handler (ev_id eid, Handler * hdlr);
    hdlr_id set_handler (const std::string ev_name, Handler * hdlr);
    Handler * unset_handler (hdlr_id hid);

    // ----------------------------------------------
    // for modules, not used for external program
    ev_id assign_event (const std::string &name);
    param_id assign_param (const std::string &name, VarFactory *fac = NULL);
    void decode (dec_id dec, Property *p);
    void build_param_vector (std::vector <Param *> * prm_vec_);
  };
}  // namespace swarm

#endif  // SRC_SWARM_H__
