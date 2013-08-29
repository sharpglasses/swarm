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
#include <string.h>

#include "../src/swarm.h"

TEST (Property, basic) {
  swarm::NetDec * nd = new swarm::NetDec ();
  swarm::Property * p = new swarm::Property (nd);
  char * a = const_cast <char *> (static_cast <const char *> ("0123456789"));

  struct timeval tv = {10, 20};
  p->init (reinterpret_cast <swarm::byte_t *> (a), strlen (a), strlen (a), tv);

  swarm::byte_t *b;

  b = p->payload (4);
  ASSERT_TRUE (NULL != b);
  EXPECT_EQ (a[0], b[0]);
  b = p->payload (4);
  ASSERT_TRUE (NULL != b);
  EXPECT_EQ (a[4], b[0]);
  b = p->payload (1);
  ASSERT_TRUE (NULL != b);
  EXPECT_EQ (a[8], b[0]);
  b = p->payload (5);
  EXPECT_TRUE (NULL == b);

  delete p;
  delete nd;
}


TEST (Property, length) {
  swarm::NetDec * nd = new swarm::NetDec ();
  swarm::Property * p = new swarm::Property (nd);
  char * a = const_cast <char *> (static_cast <const char *> ("0123456789"));
  struct timeval tv = {10, 20};
  p->init (reinterpret_cast <swarm::byte_t *> (a), sizeof (a), 5, tv);

  swarm::byte_t *b;

  b = p->payload (4);
  EXPECT_EQ (a[0], b[0]);
  b = p->payload (4);
  EXPECT_EQ (NULL, reinterpret_cast<char*> (b)); 
  b = p->payload (4);
  EXPECT_EQ (NULL, reinterpret_cast<char*> (b));

  delete p;
  delete nd;
}


TEST (Property, param) {
  const std::string p1_name = "blue";
  const std::string p2_name = "orange";
  const std::string p3_name = "red";
  swarm::NetDec * nd = new swarm::NetDec ();
  swarm::param_id p1_id = nd->assign_param (p1_name);
  swarm::param_id p2_id = nd->assign_param (p2_name);
  swarm::Property * p = new swarm::Property (nd);
  size_t len;

  char * w1 = const_cast <char *> (static_cast <const char *> ("not sane"));
  char * w2 = const_cast <char *> (static_cast <const char *> ("all is right"));
  char * w3 = const_cast <char *> (static_cast <const char *> ("the order has fallen"));

  // macro for check consistency of looking up by id and string name
#define CHECK_CONS()                                      \
  do {                                                    \
    EXPECT_TRUE (p->param (p1_id) == p->param (p1_name)); \
    EXPECT_TRUE (p->param (p2_id) == p->param (p2_name)); \
  } while (0);

  CHECK_CONS ();
  EXPECT_NE (p1_id, p2_id);
  ASSERT_TRUE (NULL != p->param (p1_id));
  ASSERT_TRUE (NULL != p->param (p1_name));
  ASSERT_TRUE (NULL != p->param (p2_id));
  ASSERT_TRUE (NULL != p->param (p2_name));
  ASSERT_TRUE (NULL == p->param (p3_name));

  const swarm::Param *p1, *p2;

  // add a value to p1
  EXPECT_EQ (true, p->set (p1_name, w1, strlen (w1)));
  CHECK_CONS ();
  EXPECT_EQ (1, p->param (p1_id)->size ());
  EXPECT_EQ (0, p->param (p2_id)->size ());

  // add a value to 2nd index of p1
  EXPECT_EQ (true, p->set (p1_name, w2, strlen (w2)));
  CHECK_CONS ();
  EXPECT_EQ (2, p->param (p1_id)->size ());
  EXPECT_EQ (0, p->param (p2_id)->size ());

  // add a value to 3rd index of p1
  EXPECT_EQ (true, p->set (p1_id, w3, strlen (w3)));
  CHECK_CONS ();
  EXPECT_EQ (3, p->param (p1_id)->size ());
  EXPECT_EQ (0, p->param (p2_id)->size ());

  // check values in p1
  p1 = p->param (p1_id);
  ASSERT_TRUE (NULL != p1);
  EXPECT_EQ (w1, p1->str ());
  EXPECT_EQ (w1, p1->str (0));
  EXPECT_EQ (w2, p1->str (1));
  EXPECT_EQ (w3, p1->str (2));
  EXPECT_EQ (swarm::Param::errmsg_, p1->str (3));
  EXPECT_TRUE (w1 == reinterpret_cast<char *> (p1->get (&len)));

  // add a value to p2
  EXPECT_EQ (true, p->copy (p2_name, w1, strlen (w1)));
  CHECK_CONS ();
  EXPECT_EQ (3, p->param (p1_id)->size ());
  EXPECT_EQ (1, p->param (p2_id)->size ());

  // add a value to 2nd index of p2
  EXPECT_EQ (true, p->copy (p2_name, w2, strlen (w2)));
  CHECK_CONS ();
  EXPECT_EQ (3, p->param (p1_id)->size ());
  EXPECT_EQ (2, p->param (p2_id)->size ());

  p1 = p->param (p1_id);
  p2 = p->param (p2_id);
  ASSERT_TRUE (NULL != p1);
  EXPECT_EQ (w1, p1->str ());
  EXPECT_EQ (w1, p1->str (0));
  EXPECT_EQ (w2, p1->str (1));
  EXPECT_EQ (w3, p1->str (2));

  ASSERT_TRUE (NULL != p2);
  EXPECT_EQ (w1, p2->str ());
  EXPECT_EQ (w2, p2->str (1));
  EXPECT_EQ (swarm::Param::errmsg_, p2->str (2));
  EXPECT_TRUE (w1 != reinterpret_cast<char *> (p2->get (&len)));


}
