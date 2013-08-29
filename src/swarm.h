#ifndef __LIB_SWARM_H__
#define __LIB_SWARM_H__

#include <sys/types.h>
#include <string>
#include <map>
#include <vector>

namespace swarm {
  typedef u_int8_t  byte_t;
  typedef u_int64_t ev_id;    // Event ID
  typedef u_int64_t param_id; // Parameter ID
  typedef u_int64_t hdlr_id;  // Handler Entry ID
  typedef int       dec_id;   // Decoder ID

  const static ev_id    EV_NULL = 0;
  const static hdlr_id  HDLR_NULL = 0;
  const static param_id PARAM_NULL = 0;
  const static dec_id   DEC_NULL = -1;

  class NetDec;
  class Var; // in var.h
  
  class Param {
  private:
    std::vector <Var *> var_set_;
    size_t idx_;

  public:
    const static std::string errmsg_;
    Param ();
    ~Param ();
    void init ();

    size_t size () const;
    void push (byte_t *data, size_t len, bool copy=false);
    byte_t * get (size_t *len = NULL, size_t idx = 0) const;

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
    ~Property ();
    void init (const byte_t *data, const size_t cap_len, 
               const size_t data_len, const struct timeval &tv);

    bool set (const std::string &param_name, void * ptr, size_t len);
    bool set (const param_id pid, void * ptr, size_t len);
    bool copy (const std::string &param_name, void * ptr, size_t len);
    bool copy (const param_id pid, void * ptr, size_t len);

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
    void emit (dec_id dec, Property *p);

  public:
    Decoder (NetDec * nd);
    virtual ~Decoder ();
    virtual void setup (NetDec *nd) = 0;
    virtual bool decode (Property *p) = 0;
  };


  class NetDec {
  private:
    std::map <std::string, ev_id> dict_event_;
    std::map <std::string, param_id> dict_param_;
    std::map <std::string, dec_id> dict_dec_;

    const std::string none_ ;
    std::vector <Decoder *> dec_mod_;
    std::vector <std::string> dec_name_;

    dec_id dec_ether_;
    
  public:
    NetDec ();
    ~NetDec ();

    bool input (const byte_t *data, const size_t cap_len, 
                const size_t data_len, const struct timeval &tv, int dlt);
    ev_id lookup_event_id (const std::string &name);
    std::string lookup_event_name (ev_id eid);
    size_t event_size () const;

    param_id lookup_param_id (const std::string &name);
    std::string lookup_param_name (param_id pid);
    size_t param_size () const;

    dec_id lookup_dec_id (const std::string &name);

    hdlr_id set_handler (ev_id eid, Handler * hdlr);
    bool unset_handler (hdlr_id hid);

    ev_id assign_event (const std::string &name);
    param_id assign_param (const std::string &name);
  };
}

#endif
