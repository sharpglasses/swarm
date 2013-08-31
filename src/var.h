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

#define __CAST(S, D)                              \
    {                                             \
      S *p = reinterpret_cast<S* > (this->ptr_);  \
      n = static_cast<D> (*p);                    \
    }

    template <typename T>  T num () const {
      if (this->len_ >= sizeof (T)) {
        T * p = reinterpret_cast <T *> (this->ptr_);
        return (this->len_ < sizeof (T) || p == NULL) ? 0 : *p;
      } else {
        // when not enough lenght, adjust to unsigned integer
        T n;

        switch (this->len_) {
        case 1:
          __CAST (u_int8_t, T); break;
        case 2:
        case 3:
          __CAST (u_int16_t, T); break;
        case 4:
        case 5:
        case 6:
        case 7:
          __CAST (u_int32_t, T); break;
        }
        return n;
      }
    }

#undef __CAST

    bool str (std::string *s) const;
    bool hex (std::string *s) const;
    bool ip4 (std::string *s) const;
    bool ip6 (std::string *s) const;
    bool mac (std::string *s) const;
  };

}  // namespace swarm

#endif  // SRC_VAR_H__
