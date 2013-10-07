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

#ifndef SRC_PROPERTY_H__
#define SRC_PROPERTY_H__

#include <assert.h>
#include <sys/types.h>
#include <string>
#include <map>
#include <vector>
#include <deque>

#include "./common.h"

namespace swarm {
  class NetDec;

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
    std::string desc_;
    VarFactory * fac_;

  public:
    ParamEntry (param_id pid, const std::string &name,
                const std::string &desc_, VarFactory * fac);
    ~ParamEntry ();
    param_id pid () const;
    const std::string& name () const;
    const std::string& desc () const;
    VarFactory * fac () const;
  };


  class Property {
  private:
    NetDec * nd_;
    time_t tv_sec_;
    time_t tv_usec_;

    // buffer for payload management
    const byte_t *buf_;
    // size_t buf_len_;
    size_t data_len_;
    size_t cap_len_;
    size_t ptr_;

    // Parameter management
    std::vector <Param *> param_;

    // Event management
    std::vector <ev_id> ev_queue_;
    size_t ev_pop_ptr_;
    size_t ev_push_ptr_;
    static const size_t EV_QUEUE_WIDTH = 128;


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

    ev_id pop_event ();
    void push_event (const ev_id eid);

    Param * param (const std::string &key) const;
    Param * param (const param_id pid) const;
    u_int64_t get_5tuple_hash () const;
    size_t len () const;      // original data length
    size_t cap_len () const;  // captured data length
    void tv (struct timeval *tv) const;
    double ts () const;

    // ToDo(masa): byte_t * refer() should be const byte_t * refer()
    byte_t * refer (size_t alloc_size);
    // ToDo(masa): byte_t * payload() should be const byte_t * payload()
    byte_t * payload (size_t alloc_size);
    size_t remain () const;

    std::string src_addr () const;
    std::string dst_addr () const;
    void *src_addr (size_t *len) const;
    void *dst_addr (size_t *len) const;
    int src_port () const;
    int dst_port () const;
    std::string proto () const;

    inline static size_t pid2idx (param_id pid) {
      return static_cast <size_t> (pid - PARAM_BASE);
    }
    inline static void addr2str (void * addr, size_t len, std::string *s);
  };
}  // namespace swarm

#endif  // SRC_PROPERTY_H__
