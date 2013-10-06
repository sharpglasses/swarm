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

namespace swarm {
  class NetDec;
  class RealtimeTimer;
  class Task;

  class NetCap {
  private:
    NetDec *nd_;
    pcap_t *pcap_;
    int dlt_;
    std::string errmsg_;
    RealtimeTimer *timer_;

    static const int PCAP_BUFSIZE_ = 0xffff;
    static const int PCAP_TIMEOUT_ = 1;
    static bool set_pcap_filter (pcap_t *pd, const std::string &filter,
                                 std::string *errmsg);

  public:
    explicit NetCap (NetDec *nd = NULL);
    ~NetCap ();
    void set_netdec (NetDec *nd);
    bool add_device (const std::string &dev, const std::string &filter="");
    bool add_pcapfile (const std::string &dev, const std::string &filter="");
    bool start ();

    bool capture (const std::string &dev, const std::string &filter="");
    bool capture_alldev (const std::string &filter="");
    bool read_pcapfile (const std::string &file, const std::string &filter="");

    task_id set_onetime_timer (Task *task, int delay_msec);
    task_id set_repeat_timer (Task *task, int interval_msec);
    bool unset_timer (task_id id);

    const std::string &errmsg () const;
  };
}  //  namespace swarm

#endif  // SRC_NETCAP_H__
