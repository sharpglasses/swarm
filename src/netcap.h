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

#ifndef SRC_NETCAP_H__
#define SRC_NETCAP_H__

#include <string>
#include "./common.h"
#include "./timer.h"

namespace swarm {
  class NetDec;
  class RealtimeTimer;
  class Task;

  // ----------------------------------------------------------------
  // class NetCap:
  // Base class of traffic capture classes. In this version, swarm supports
  // only pcap based capture. However it will support other capture method
  // such as etherpipe (https://github.com/sora/ethpipe).
  //
  class NetCap {
  public:
    enum Status {
      READY = 0,
      RUNNING,
      STOP,
      FAIL,
    };

  private:
    NetDec *nd_;
    RealtimeTimer *timer_;
    std::string errmsg_;
    Status status_;

  protected:
    inline NetDec *netdec() { return this->nd_; }
    inline void timer_proc () {
      if (this->timer_->ready ()) {
        this->timer_->fire ();
      }
    }
    void set_errmsg(const std::string &errmsg);
    void set_status(Status st);
    virtual bool run () = 0;

  public:
    explicit NetCap ();
    virtual ~NetCap ();
    void connect (NetDec *nd);
    inline Status status () const { return this->status_; }
    inline bool ready () const { return (this->status_ == READY); }
    bool start ();

    task_id set_onetime_timer (Task *task, int delay_msec);
    task_id set_repeat_timer (Task *task, int interval_msec);
    bool unset_timer (task_id id);

    const std::string &errmsg () const;
  };

  // ----------------------------------------------------------------
  // class PcapBase:
  // Implemented common pcap functions for CapPcapDev and CapPcapFile
  //
  class PcapBase : public NetCap {
  protected:
    pcap_t *pcap_;
    std::string filter_;
    static const size_t PCAP_BUFSIZE_ = 0xffff;
    static const size_t PCAP_TIMEOUT_ = 1;

    bool run ();

  public:
    PcapBase ();
    virtual ~PcapBase ();
    bool set_filter (const std::string &filter);
  };

  // ----------------------------------------------------------------
  // class CapPcapDev:
  // Capture live traffic via pcap library from network device
  //
  class CapPcapDev : public PcapBase {
  private:
    std::string dev_name_;

  public:
    explicit CapPcapDev (const std::string &dev_name);
    ~CapPcapDev ();
  };

  // ----------------------------------------------------------------
  // class CapPcapDev:
  // Capture stored traffic via pcap library from file
  //
  class CapPcapFile : public PcapBase {
  private:
    std::string file_path_;

  public:
    explicit CapPcapFile (const std::string &file_path);
    ~CapPcapFile ();
  };

}  //  namespace swarm

#endif  // SRC_NETCAP_H__
