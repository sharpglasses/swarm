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

#include <time.h>
#include <pcap.h>
#include <string.h>

#include "./gtest.h"
#include "../src/debug.h"
#include "../src/swarm.h"

TEST(Timer, set) {
  class Worker : public swarm::Task {
  public:
    int i_;
    Worker() : i_(0) {}
    void exec(const struct timespec &ts) { 
      i_++; 
    }
  };

  Worker *w = new Worker();
  swarm::NetCap *nc = new swarm::CapPcapDev("en0");
  swarm::task_id tid1 = nc->set_periodic_task(w, 1.);
  swarm::task_id tid2 = nc->set_periodic_task(w, 1.5);
  EXPECT_NE(tid1, tid2);
  EXPECT_TRUE(nc->unset_task(tid1));
  EXPECT_FALSE(nc->unset_task(tid1));
  EXPECT_TRUE(nc->unset_task(tid2));
  EXPECT_FALSE(nc->unset_task(tid2));
}

