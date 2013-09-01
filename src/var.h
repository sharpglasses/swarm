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


#ifndef SRC_VAR_H__
#define SRC_VAR_H__

#include <string>

#include "./swarm.h"

namespace swarm {
  class Var {
  private:
    byte_t * ptr_;
    byte_t * buf_;
    size_t len_;
    size_t buf_len_;

  public:
    Var ();
    ~Var ();
    void init ();
    void set (byte_t *ptr, size_t len);
    void copy (byte_t *ptr, size_t len);
    byte_t * get (size_t *len) const;
    virtual bool repr (std::string *s) const;

    template <typename T>  T num () const {
      if (this->len_ >= sizeof (T)) {
        T * p = reinterpret_cast <T *> (this->ptr_);
        return (this->len_ < sizeof (T) || p == NULL) ? 0 : *p;
      } else {
        // when not enough lenght, adjust to unsigned integer
        T n;

        if (this->len_ == 1) {
          u_int8_t *p = reinterpret_cast<u_int8_t* > (this->ptr_);
          n = static_cast<T> (*p);
        } else if (2 == this->len_ || 3 == this->len_) {
          u_int16_t *p = reinterpret_cast<u_int16_t* > (this->ptr_);
          n = static_cast<T> (ntohs (*p));
        } else if (4 <= this->len_ && this->len_ <= 7) {
          u_int32_t *p = reinterpret_cast<u_int32_t* > (this->ptr_);
          n = static_cast<T> (ntohl (*p));
        }

        return n;
      }
    }

    bool str (std::string *s) const;
    bool hex (std::string *s) const;
    bool ip4 (std::string *s) const;
    bool ip6 (std::string *s) const;
    bool mac (std::string *s) const;
  };

  class VarFactory {
  public:
    VarFactory () {}
    virtual ~VarFactory () {}
    virtual Var * New () { return new Var (); }
  };

#define DEF_REPR_CLASS(V_NAME, F_NAME)            \
  class V_NAME : public Var {                     \
  public:  bool repr (std::string *s) const;      \
  };                                              \
  class F_NAME : public VarFactory {              \
  public: Var * New () { return new V_NAME (); }  \
  };


  // extended classes
  DEF_REPR_CLASS (VarIPv4, FacIPv4);
  DEF_REPR_CLASS (VarNum,  FacNum);


}  // namespace swarm

#endif  // SRC_VAR_H__
