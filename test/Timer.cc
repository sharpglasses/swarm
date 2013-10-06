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

#define __TEST_C(T, M, C)                       \
  {                                             \
    struct timespec ts = {10, 0};               \
    ts.tv_sec += ((M) / 1000);                  \
    ts.tv_nsec = ((M) % 1000) * 1000 * 1000;    \
    timer.ticktock (ts);                        \
    EXPECT_EQ ((C), (T)->count ());             \
  }

TEST (Timer, basic) {
  swarm::Timer timer;
  TimeCounter *tc = new TimeCounter ();
  swarm::task_id t_id = timer.install_task(tc, swarm::Timer::ONCE, 100);
  ASSERT_NE (swarm::TASK_NULL, t_id);

  __TEST_C (tc,   0, 0);
  __TEST_C (tc,  50, 0);
  __TEST_C (tc, 100, 1);
  __TEST_C (tc, 200, 1);
}


TEST (Timer, multiple_once) {
  swarm::Timer timer;
  TimeCounter *tc = new TimeCounter ();

  ASSERT_NE (swarm::TASK_NULL,
             timer.install_task(tc, swarm::Timer::ONCE, 100));
  ASSERT_NE (swarm::TASK_NULL,
             timer.install_task(tc, swarm::Timer::ONCE, 200));
  ASSERT_NE (swarm::TASK_NULL,
             timer.install_task(tc, swarm::Timer::ONCE, 300));
  ASSERT_NE (swarm::TASK_NULL,
             timer.install_task(tc, swarm::Timer::ONCE, 400));
  ASSERT_NE (swarm::TASK_NULL,
             timer.install_task(tc, swarm::Timer::ONCE, 1200));

  __TEST_C (tc,    0, 0);
  __TEST_C (tc,   50, 0);
  __TEST_C (tc,   99, 0);
  __TEST_C (tc,  100, 1);
  __TEST_C (tc,  101, 1);
  __TEST_C (tc,  220, 2);
  __TEST_C (tc,  500, 4);
  __TEST_C (tc, 1199, 4);
  __TEST_C (tc, 1200, 5);
  __TEST_C (tc, 1201, 5);
}


TEST (Timer, repeat) {
  swarm::Timer timer;
  TimeCounter *tc = new TimeCounter ();
  timer.install_task(tc, swarm::Timer::REPEAT, 100);

  __TEST_C (tc,   0, 0);
  __TEST_C (tc,  99, 0);
  __TEST_C (tc, 100, 1);
  __TEST_C (tc, 101, 1);
  __TEST_C (tc, 199, 1);
  __TEST_C (tc, 200, 2);
  __TEST_C (tc, 201, 2);
}

TEST (Timer, repeat_time_adjust) {
  swarm::Timer timer;
  TimeCounter *tc = new TimeCounter ();
  timer.install_task(tc, swarm::Timer::REPEAT, 100);

  __TEST_C (tc,   0, 0);
  __TEST_C (tc,  99, 0);
  __TEST_C (tc, 199, 1);
  // Adjust time based on previous target tick
  __TEST_C (tc, 200, 2);
  __TEST_C (tc, 201, 2);
  // If there is big delay, adjust time based on current tick
  __TEST_C (tc, 450, 3);
  __TEST_C (tc, 549, 3);
  __TEST_C (tc, 550, 4);
}

TEST (Timer, intall_remove) {
  swarm::Timer timer;
  TimeCounter *tc = new TimeCounter ();
  swarm::task_id t_id =
    timer.install_task(tc, swarm::Timer::REPEAT, 100);
  ASSERT_NE (swarm::TASK_NULL, t_id);
  EXPECT_EQ (true, timer.remove_task (t_id));
  EXPECT_EQ (false, timer.remove_task (t_id));

  __TEST_C (tc,   0, 0);
  __TEST_C (tc, 200, 0);
}


TEST (RealtimeTimer, repeat_time_adjust) {
  swarm::RealtimeTimer timer;
  TimeCounter *tc1 = new TimeCounter ();
  TimeCounter *tc2 = new TimeCounter ();
  timer.install_task(tc1, swarm::Timer::REPEAT, 100);
  timer.install_task(tc2, swarm::Timer::ONCE,   300);

  timer.start ();
  const struct timespec ts = {0, 100000};
  struct timeval tv_s, tv_e, delta = {0, 0};
  gettimeofday (&tv_s, NULL);
  while (delta.tv_sec == 0) {
    nanosleep (&ts, NULL);
    if (timer.ready ()) {
      timer.fire ();
    }
    gettimeofday (&tv_e, NULL);
    timersub (&tv_e, &tv_s, &delta);
  }
  timer.stop ();

  EXPECT_GT (12, tc1->count ());
  EXPECT_LT (8,  tc1->count ());
  EXPECT_EQ (1,  tc2->count ());
}

