#ifndef __LIB_SWARM_VAR_H__
#define __LIB_SWARM_VAR_H__

#include "swarm.h"

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

    template <typename T>  T num () {
      T * p = reinterpret_cast <T *> (this->ptr_);
      return (this->len_ < sizeof (T) || p == NULL) ? 0 : *p;
    }

    bool str (std::string *s, char ng = '.');
    bool hex (std::string *s);
    bool ip4 (std::string *s);
    bool ip6 (std::string *s);
    bool mac (std::string *s);    
  };

}

#endif
