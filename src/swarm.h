#ifndef __LIB_SWARM_H__
#define __LIB_SWARM_H__

#include <sys/types.h>
#include <string>
#include <map>
#include <vector>

namespace swarm {
  typedef u_int8_t  byte_t;
  typedef u_int64_t ev_id;  // Event ID
  typedef u_int64_t param_id; // Parameter ID
  typedef u_int64_t hdlr_id;  // Handler Entry ID

  const static ev_id    EV_NULL = 0;
  const static hdlr_id  HDLR_NULL = 0;
  const static param_id PARAM_NULL = 0;

  class NetDec;

  class Param {
  public:
    size_t size () const;
    byte_t * get (size_t idx, size_t *len) const;
    bool str (size_t idx, std::string *s) const;

  };

  class Property {
  private:
    NetDec * nd_;
    time_t tv_sec_;
    time_t tv_usec_;

    byte_t *buf_;
    size_t buf_len_;
    size_t data_len_;
    size_t cap_len_;
    std::vector <Param *> param_;
    size_t ptr_;

  public:
    Property (NetDec * nd);
    void init ();
    Param * param (const std::string &key) const;
    Param * param (const param_id pid) const;
    byte_t * payload (size_t alloc_size);
  };

  class Handler {
  public:
    Handler ();
    virtual ~Handler ();
    virtual void recv (ev_id eid, const Property &p) = 0;
  };

  class Decoder {
  private:
    NetDec * nd_;

  protected:
    void emit (Property *p);

  public:
    Decoder (NetDec * nd);
    virtual ~Decoder ();
    virtual bool decode (Property *p) = 0;
  };


  class NetDec {
  private:
    std::map <std::string, ev_id> dict_event_;
    const std::string none_ ;
    std::vector <Decoder *> decoder_;

  public:
    NetDec ();
    ~NetDec ();
    
    bool input (const byte_t *data, const size_t cap_len, 
                const size_t data_len, const struct timeval &tv);
    ev_id lookup_ev_id (const std::string &name);
    std::string lookup_ev_name (ev_id eid);
    param_id lookup_param_id (const std::string &name);
    std::string lookup_param_name (param_id pid);

    hdlr_id set_handler (ev_id eid, Handler * hdlr);
    bool unset_handler (hdlr_id hid);

    ev_id assign_event (const std::string &name);
    param_id assign_param (const std::string &name);
  };
}

#endif
