// Copyright 2024 The GWPSan Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "gwpsan/base/bazel.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sstream>

#include "gtest/gtest.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/os.h"

namespace gwpsan {
namespace {

TEST(Bazel, OnPrint) {
  const char* path = getenv("TEST_UNDECLARED_OUTPUTS_DIR");
  if (!path)
    GTEST_SKIP() << "not running under Bazel";
  // Print something and check that it's in the file.
  const char* kMyOutput = "Hello, Bazel test!\n";
  Printf("%s", kMyOutput);
  std::ostringstream file;
  file << path << "/gwpsan." << getpid() << ".txt";
  char output[4096];
  EXPECT_TRUE(!!ReadFile(file.str().c_str(), output));
  EXPECT_TRUE(strstr(output, kMyOutput));

  // Now log something and check that it's in the file.
  const char* kMyLog = "Logging for Bazel";
  bool old_log_enabled = log_enabled;
  log_enabled = true;
  SAN_LOG("%s", kMyLog);
  log_enabled = old_log_enabled;
  EXPECT_TRUE(!!ReadFile(file.str().c_str(), output));
  EXPECT_TRUE(strstr(output, kMyLog));
}

TEST(Bazel, Warning) {
  const char* file = getenv("TEST_WARNINGS_OUTPUT_FILE");
  if (!file)
    GTEST_SKIP() << "not running under Bazel";
  EXPECT_FALSE(BazelReportedWarning());
  BazelOnReport("a warning");
  EXPECT_TRUE(BazelReportedWarning());
  char output[4096];
  EXPECT_TRUE(!!ReadFile(file, output));
  EXPECT_TRUE(strstr(output, "[gwpsan] a warning\n"));
}

}  // namespace
}  // namespace gwpsan
