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

#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define GWPSAN_TEST  // allow all libc calls

#include "gwpsan/base/array.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/vector.h"
#include "gwpsan/core/arch.h"
#include "gwpsan/core/decode.h"
#include "gwpsan/core/semantic_metadata.h"

#pragma clang diagnostic ignored "-Wframe-larger-than"

namespace gwpsan {
#if GWPSAN_DEBUG
namespace {

template <typename T>
void ReadObj(int fd, uptr off, T& obj) {
  if (pread(fd, &obj, sizeof(obj), off) != sizeof(obj))
    errx(1, "read failed");
}

struct Opcode {
  const char* name;
  uptr decoded;
  uptr atomic_instr;     // as decoded
  uptr atomic_meta;      // according to metadata
  uptr atomic_both;      // both as decoded and according to metadata
  uptr atomic_unmarked;  // atomic as decoded, but metadata says it's not
  uptr failed;
  uptr failed_pc;
  char* failed_error;
};

using OpcodeArray = Array<Opcode, ArchDecoder::kMaxOpcodes>;

void ProcessText(OpcodeArray& opcodes, uptr begin, uptr end, const char* name) {
  if (begin == end)
    return;
  printf("  section %s 0x%zx-0x%zx (0x%zx): ", name, begin, end, end - begin);
  bool print_failed = false;
  uptr prev_pc = 0;
  uptr ninstr = 0;
  uptr ndecoded = 0;
  uptr size = 0;
  for (uptr pc = begin; pc < end; pc += size, ninstr++) {
    ArchDecoder dec(pc);
    bool ok = dec.Decode();
    size = dec.GetByteSize();
    if (size == 0) {
      if (!print_failed) {
        print_failed = true;
        printf("FAILED TO DECODE 0x%zx\n", pc);
        if (prev_pc)
          printf("prev instruction 0x%zx: %s\n", prev_pc,
                 &DumpInstr(prev_pc, kDumpRaw));
        printf("instruction bytes:");
        for (uptr i = 0; i < kMaxInstrLen && pc + i < end; i++)
          printf("  0x%02x", ((u8*)pc)[i]);
        printf("\n");
      }
      opcodes[0].failed++;
      size = 1;
      continue;
    }
    prev_pc = pc;
    const char* name = nullptr;
    uptr index = dec.GetOpcode(name);
    auto& opcode = opcodes.at(index);
    opcode.name = name;
    if (ok) {
      ndecoded++;
      opcode.decoded++;
      opcode.atomic_instr += dec.IsAtomic();
      auto meta_atomic = IsAtomicPC(pc);
      if (meta_atomic) {
        if (*meta_atomic) {
          opcode.atomic_meta++;
          if (dec.IsAtomic())
            opcode.atomic_both++;
        } else if (dec.IsAtomic()) {
          opcode.atomic_unmarked++;
          printf("UNMARKED ATOMIC: %s\n", &DumpInstr(pc, kDumpRaw));
        }
      }
      continue;
    }
    if (dec.hard_failed())
      printf("FAILED: %s: %s\n", &DumpInstr(pc, kDumpRaw), dec.failed());
    if (opcode.failed == 0) {
      opcode.failed_pc = pc;
      opcode.failed_error = strdup(dec.failed());
    }
    opcode.failed++;
  }
  printf("decoded %zu/%zu\n", ndecoded, ninstr);
}

void ProcessFile(OpcodeArray& opcodes, dl_phdr_info* info) {
  int fd =
      open(info->dlpi_name[0] ? info->dlpi_name : "/proc/self/exe", O_RDONLY);
  SAN_CHECK_NE(fd, -1);
  ElfW(Ehdr) ehdr;
  ReadObj(fd, 0, ehdr);
  ElfW(Shdr) names;
  ReadObj(fd, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, names);
  MallocVector<char> name_data;
  name_data.resize(names.sh_size);
  if (pread(fd, &name_data[0], name_data.size(), names.sh_offset) !=
      name_data.size())
    errx(1, "read failed");
  for (uptr i = 0; i < ehdr.e_shnum; i++) {
    ElfW(Shdr) shdr;
    ReadObj(fd, ehdr.e_shoff + i * ehdr.e_shentsize, shdr);
    if (shdr.sh_type != SHT_PROGBITS || !(shdr.sh_flags & SHF_ALLOC) ||
        !(shdr.sh_flags & SHF_EXECINSTR))
      continue;
    const char* name = &name_data.at(shdr.sh_name);
    uptr begin = info->dlpi_addr + shdr.sh_addr;
    uptr end = begin + shdr.sh_size;
    ProcessText(opcodes, begin, end, name);
  }
}

void ProcessMemory(OpcodeArray& opcodes, dl_phdr_info* info) {
  for (uptr i = 0; i < info->dlpi_phnum; i++) {
    const auto& phdr = info->dlpi_phdr[i];
    if ((phdr.p_type != PT_LOAD) || !(phdr.p_flags & PF_X))
      continue;
    uptr begin = info->dlpi_addr + phdr.p_vaddr;
    uptr end = begin + phdr.p_memsz;
    ProcessText(opcodes, begin, end, ".text");
  }
}
}  // namespace

// Decodes all executable segments and prints stats on successfully decoded
// and failed instructions and opcodes.
void DumpInstructions() {
  OpcodeArray opcodes = {};
  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t, void* arg) {
        OpcodeArray& opcodes = *static_cast<OpcodeArray*>(arg);
        const char* name = strrchr(info->dlpi_name, '/');
        if (name)
          name++;
        else
          name = info->dlpi_name;
        printf("processing module %s\n", name);
        if (strstr(info->dlpi_name, "linux-vdso.so"))
          ProcessMemory(opcodes, info);
        else
          ProcessFile(opcodes, info);
        return 0;
      },
      &opcodes);
  uptr total_instrs = 0;
  uptr total_decoded = 0;
  uptr total_atomic_instr = 0;
  uptr total_atomic_meta = 0;
  uptr total_atomic_both = 0;
  uptr total_atomic_unmarked = 0;
  uptr total_failed = 0;
  uptr total_opcodes = 0;
  uptr total_opcodes_decoded = 0;
  uptr total_opcodes_failed = 0;
  printf("%-16s %-8s %-8s\n", "opcode", "decoded", "failed");
  for (const auto& opcode : opcodes) {
    if (!opcode.name || opcode.decoded + opcode.failed == 0)
      continue;
    total_instrs += opcode.decoded + opcode.failed;
    total_decoded += opcode.decoded;
    total_atomic_instr += opcode.atomic_instr;
    total_atomic_meta += opcode.atomic_meta;
    total_atomic_both += opcode.atomic_both;
    total_atomic_unmarked += opcode.atomic_unmarked;
    total_failed += opcode.failed;
    total_opcodes++;
    total_opcodes_decoded += !!opcode.decoded;
    total_opcodes_failed += !!opcode.failed;
    printf("%-16s %8zu %8zu", opcode.name, opcode.decoded, opcode.failed);
    if (opcode.failed)
      printf(" sample: %s", &DumpInstr(opcode.failed_pc, kDumpRaw));
    printf("\n");
  }
  printf("garbage instructions %zu\n", opcodes[0].failed);
  if (total_instrs == 0)
    return;
  printf(
      "instructions %zu, decoded %zu (%.2f%%), failed %zu "
      "(%.2f%%)\n",
      total_instrs, total_decoded, total_decoded * 100.0 / total_instrs,
      total_failed, total_failed * 100.0 / total_instrs);
  printf("atomic instructions %zu, metadata %zu, both %zu, unmarked %zu\n",
         total_atomic_instr, total_atomic_meta, total_atomic_both,
         total_atomic_unmarked);
  printf("opcodes %zu, decoded %zu (%.2f%%), failed %zu (%.2f%%)\n",
         total_opcodes, total_opcodes_decoded,
         total_opcodes_decoded * 100.0 / total_opcodes, total_opcodes_failed,
         total_opcodes_failed * 100.0 / total_opcodes);
  fflush(nullptr);
}
#else   // #if GWPSAN_DEBUG
void DumpInstructions() {
  Printf("instruction dumper isn't compiled it, rebuild with -DGWPSAN_DEBUG\n");
}
#endif  // #if GWPSAN_DEBUG
}  // namespace gwpsan
