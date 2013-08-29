#include "var.h"
#include "debug.h"
#include <arpa/inet.h>

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
  }

  byte_t * Var::get (size_t *len) const {
    *len = this->len_;
    return this->ptr_;
  }


  bool Var::str (std::string *s) const { 
    if (this->ptr_) {
      s->assign (reinterpret_cast<char *> (this->ptr_), this->len_);
      return true;
    }
    else {
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


}
