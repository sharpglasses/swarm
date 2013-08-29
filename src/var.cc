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

#include "./var.h"
#include "./debug.h"

namespace swarm {
  // -------------------------------------------------------
  // Var
  Var::Var () : buf_(NULL),  len_(0), buf_len_(0) {
  }
  Var::~Var () {
    if (this->buf_) {
      free (this->buf_);
    }
  }
  void Var::init () {
    this->ptr_ = NULL;
    this->len_ = 0;
  }
  void Var::set (byte_t *ptr, size_t len) {
    this->ptr_ = ptr;
    this->len_ = len;
  }
  void Var::copy (byte_t *ptr, size_t len) {
    if (this->buf_len_ < len) {
      this->buf_len_ = len;
      this->buf_ = static_cast <byte_t*> (realloc (this->buf_, this->buf_len_));
    }

    ::memcpy (this->buf_, ptr, len);
    this->ptr_ = this->buf_;
    this->len_ = len;
  }

  byte_t * Var::get (size_t *len) const {
    if (len) {
      *len = this->len_;
    }
    return this->ptr_;
  }


  bool Var::str (std::string *s) const { 
    if (this->ptr_) {
      s->assign (reinterpret_cast<char *> (this->ptr_), this->len_);
      return true;
    } else {
      return false; 
    }
  }

  bool Var::hex (std::string *s) const { 
    std::string &buf = *s;
    byte_t * p = this->ptr_;

    if (p) {
      buf = "";
      for (size_t i = 0; i < this->len_; i++) {
        char t[4];
        snprintf (t, sizeof (t), "%02X", p[i]);
        buf += t;

        if (i < this->len_ - 1) {
          buf += " ";
        }
      }
      return true;
    }

    return false; 
  }

  bool Var::ip4 (std::string *s) const { 
    byte_t * p = this->ptr_;

    if (p && this->len_ >= 4) {
      char t[32];
      ::inet_ntop (PF_INET, static_cast<void*>(p), t, sizeof (t));
      s->assign (t);
      return true;
    }

    return false; 
  }

  bool Var::ip6 (std::string *s) const { 
    byte_t * p = this->ptr_;

    if (p && this->len_ >= 16) {
      char t[128];
      ::inet_ntop (PF_INET6, static_cast<void*>(p), t, sizeof (t));
      s->assign (t);
      return true;
    }

    return false; 
  }

  bool Var::mac (std::string *s) const { 
    std::string &buf = *s;
    byte_t * p = this->ptr_;

    if (p && this->len_ == 6) {
      buf = "";
      for (size_t i = 0; i < this->len_; i++) {
        char t[4];
        snprintf (t, sizeof (t), "%02X", p[i]);
        buf += t;
        if (i < this->len_ - 1) {
          buf += ":";
        }
      }
      return true;
    }

    return false; 
  }
} // namespace swarm
