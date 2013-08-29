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
#include "../src/swarm.h"

TEST (Param, basic) {
  swarm::Param * param = new swarm::Param ();
  swarm::byte_t * a = 
    const_cast <swarm::byte_t *> (reinterpret_cast <const swarm::byte_t *> ("0123456789"));
  std::string err = swarm::Param::errmsg_;
  param->init ();
  
#define __TEST(IDX,PTR,LEN,S32,U32,STR,HEX,IP4,IP6,MAC) \
  do {                                                  \
    size_t len;                                         \
    swarm::byte_t *p = param->get (&len, IDX);          \
    EXPECT_EQ ((PTR), p);                               \
    if (p) {                                            \
      EXPECT_EQ ((LEN), len);                           \
    }                                                   \
    int32_t n1 = param->int32 (IDX);                    \
    u_int32_t n2 = param->uint32 (IDX);                 \
    EXPECT_EQ ((S32), n1);                              \
    EXPECT_EQ ((U32), n2);                              \
    EXPECT_EQ ((STR), param->str(IDX));                 \
    EXPECT_EQ ((HEX), param->hex(IDX));                 \
    EXPECT_EQ ((IP4), param->ip4(IDX));                 \
    EXPECT_EQ ((IP6), param->ip6(IDX));                 \
    EXPECT_EQ ((MAC), param->mac(IDX));                 \
  } while (0);

  EXPECT_EQ (0, param->size ());
  __TEST (0, NULL, 0, 0, 0, err, err, err, err, err);
  __TEST (1, NULL, 0, 0, 0, err, err, err, err, err);
  __TEST (2, NULL, 0, 0, 0, err, err, err, err, err);

  param->push (a, 4);
  EXPECT_EQ (1, param->size ());

  u_int32_t *u32[2];
  int32_t *s32[2];
  u32[0] = reinterpret_cast <u_int32_t*> (a);
  s32[0] = reinterpret_cast <int32_t*> (a);
  u32[1] = reinterpret_cast <u_int32_t*> (&a[3]);
  s32[1] = reinterpret_cast <int32_t*> (&a[3]);
  __TEST (0, a, 4, *s32[0], *u32[0], "0123", "30 31 32 33", "48.49.50.51", err, err);
  __TEST (1, NULL, 0, 0, 0, err, err, err, err, err);
  __TEST (2, NULL, 0, 0, 0, err, err, err, err, err);


  param->push (&a[3], 4, true);
  swarm::byte_t *copied_ptr = param->get (NULL, 1);
  EXPECT_EQ (2, param->size ());
  __TEST (0, a, 4, *s32[0], *u32[0], "0123", "30 31 32 33", "48.49.50.51", err, err);
  __TEST (1, copied_ptr, 4, *s32[1], *u32[1], "3456", "33 34 35 36", "51.52.53.54", err, err);
  __TEST (2, NULL, 0, 0, 0, err, err, err, err, err);

#undef __TEST

  delete param;
}
