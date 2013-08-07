#include <gtest/gtest.h>
#include "swarm.h"

TEST (Param, basic) {
  swarm::Param * param = new swarm::Param ();
  swarm::byte_t * a = 
    const_cast <swarm::byte_t *> (reinterpret_cast <const swarm::byte_t *> ("0123456789"));
  std::string err = swarm::Param::errmsg_;
  size_t len;
  param->init ();
  
#define __TEST(IDX,PTR,LEN,S32,U32,S64,U64,STR,HEX,IP4,IP6,MAC) \
  do {                                                          \
    EXPECT_EQ ((PTR), param->get (&len, IDX));                   \
    EXPECT_EQ ((LEN), len);                                      \
    EXPECT_EQ ((S32), param->int32 (IDX));                       \
    EXPECT_EQ ((U32), param->uint32 (IDX));                      \
    EXPECT_EQ ((S64), param->int64 (IDX));                       \
    EXPECT_EQ ((U64), param->uint64 (IDX));                      \
    EXPECT_EQ ((STR), param->str(IDX));                          \
    EXPECT_EQ ((HEX), param->hex(IDX));                          \
    EXPECT_EQ ((IP4), param->ip4(IDX));                          \
    EXPECT_EQ ((IP6), param->ip6(IDX));                          \
    EXPECT_EQ ((MAC), param->mac(IDX));                          \
  } while (0);

  __TEST (0, NULL, 0, 0, 0, 0, 0, err, err, err, err, err);
  __TEST (1, NULL, 0, 0, 0, 0, 0, err, err, err, err, err);
  __TEST (2, NULL, 0, 0, 0, 0, 0, err, err, err, err, err);
  param->push (a, 4);

  u_int32_t *u32 = (u_int32_t*) (a);
  int32_t *s32 = (int32_t*) (a);
  __TEST (0, a, 4, *s32, *u32, 0, 0, "0123", "30 31 32 33", "33.32.31.30", err, err);
  __TEST (1, NULL, 0, 0, 0, 0, 0, err, err, err, err, err);
  __TEST (2, NULL, 0, 0, 0, 0, 0, err, err, err, err, err);


  param->push (&a[3], 4);
  u32 = (u_int32_t*) (&a[3]);
  s32 = (int32_t*) (&a[3]);
  __TEST (0, a, 4, *s32, *u32, 0, 0, "0123", "30 31 32 33", "33.32.31.30", err, err);
  __TEST (1, &a[3], 4, *s32, *u32, 0, 0, "3456", "33 34 35 36", "36.35.34.33", err, err);
  __TEST (2, NULL, 0, 0, 0, 0, 0, err, err, err, err, err);

#undef __TEST

  delete param;
}
