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

#include <gtest/gtest.h>
#include <pcap.h>
#include <string.h>

#include "../src/debug.h"
#include "../src/swarm.h"

class TimeCounter : public swarm::Task {
 private:
  int count_;

 public:
  TimeCounter () : count_(0) {}
  int count () const { return this->count_; }
  void exec (const struct timespec &tv) {
    this->count_++;
  }
};

TEST (Timer, basic) {
  swarm::Timer timer;
  struct timespec ts = {10, 0};
  TimeCounter *tc = new TimeCounter ();
  swarm::task_id t_id = timer.install_task(tc, swarm::Timer::ONCE, 100);
  ASSERT_NE (swarm::TASK_NULL, t_id);

  timer.ticktock (ts);
  EXPECT_EQ (0, tc->count ());

  ts.tv_nsec = 50 * 1000 * 1000;
  timer.ticktock (ts);
  EXPECT_EQ (0, tc->count ());

  ts.tv_nsec = 100 * 1000 * 1000;
  timer.ticktock (ts);
  EXPECT_EQ (1, tc->count ());

  ts.tv_nsec = 200 * 1000 * 1000;
  timer.ticktock (ts);
  EXPECT_EQ (1, tc->count ());
}
