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

#include "gwpsan/core/semantic_metadata.h"

#include "gwpsan/base/algorithm.h"
#include "gwpsan/base/common.h"
#include "gwpsan/base/fault_inject.h"
#include "gwpsan/base/log.h"
#include "gwpsan/base/metric.h"
#include "gwpsan/base/module_list.h"
#include "gwpsan/base/optional.h"
#include "gwpsan/base/signal.h"
#include "gwpsan/base/synchronization.h"
#include "gwpsan/base/unwind.h"
#include "gwpsan/base/vector.h"

namespace gwpsan {
namespace {
DEFINE_METRIC(metadata_covered, 0, "Metadata total covered functions");
DEFINE_METRIC(metadata_covered_atomics, 0,
              "Metadata covered with atomics functions");
DEFINE_METRIC(metadata_covered_uar, 0, "Metadata covered with UAR functions");
DEFINE_METRIC(metadata_atomics, 0, "Metadata atomic operations");

using AtomicsVector = MallocVector<uptr>;
using LoadFunc = void (*)(u32, const char*, const char* start);

constexpr u32 kNoAtomics = -1u;

struct DelayedMetadata {
  LoadFunc fn;
  u32 version;
  const char* start;
  const char* end;
};

struct MetaFunc {
  u32 offset;  // from MetaModule::start_pc
  u32 size;
  u32 stack_args_size;
  SemanticFlags features;  // features covered in this function
  u32 atomic_flat_idx;     // in MetaModule::atomics or kNoAtomics
};

struct MetaModule {
  uptr start_pc = 0;
  uptr end_pc = 0;
  MallocVector<MetaFunc> funcs;
  // List of list of atomics PCs. We can't just have a single vector, because
  // the lazy processing of pending atomics may happen from signal handlers, and
  // appending to a single vector may cause an allocation. Instead, we just move
  // the AtomicVector allocated in the constructor into a pre-allocated slot.
  MallocVector<AtomicsVector> atomics;

  const uptr* GetAtomicPC(u32 atomic_flat_idx) const {
    // Avoid touching the atomics array (separate cache line).
    if (atomic_flat_idx == kNoAtomics)
      return nullptr;

    // Calculate index into atomics based on flat index.
    u32 atomic_inner_idx = atomic_flat_idx;
    auto mod_atomics = atomics.begin();
    while (atomic_inner_idx >= mod_atomics->size()) {
      atomic_inner_idx -= mod_atomics->size();
      mod_atomics++;
    }
    return &mod_atomics->at(atomic_inner_idx);
  }
};

// The following variables are changed only during program initialization,
// so they are not protected by the mutex.
bool inited;
SemanticFlags needed_features;
constinit OptionalBase<MallocVector<DelayedMetadata>> delayed_metadata;

SemanticFlags covered_features;
constinit Mutex semantic_mtx;
constinit OptionalBase<MallocVector<MetaModule>> modules
    SAN_GUARDED_BY(semantic_mtx);
constinit OptionalBase<MallocVector<AtomicsVector>> pending_atomics
    SAN_GUARDED_BY(semantic_mtx);
constinit bool modules_sorted SAN_GUARDED_BY(semantic_mtx) = true;
constinit bool modules_compacted SAN_GUARDED_BY(semantic_mtx) = true;
// Cached last module/func that we searched for.
constinit MetaModule* last_module SAN_GUARDED_BY(semantic_mtx);
constinit MetaFunc* last_func SAN_GUARDED_BY(semantic_mtx);

void CompactModules() SAN_REQUIRES(semantic_mtx) {
  modules_compacted = true;
  uptr pos = 0;
  for (uptr i = 0; i < modules->size(); ++i) {
    auto& mod = (*modules)[i];
    if (mod.end_pc <= mod.start_pc)
      continue;
    if (i != pos)
      (*modules)[pos] = move(mod);
    pos++;
  }
  modules->shrink(pos);
}

void SortModules() SAN_REQUIRES(semantic_mtx) {
  modules_sorted = true;
  sort(modules->begin(), modules->end(),
       [](const MetaModule& a, const MetaModule& b) -> bool {
         return a.start_pc < b.start_pc;
       });
}

void AddAtomics(MetaModule& mod, AtomicsVector&& atomics)
    SAN_REQUIRES(semantic_mtx) {
  // There must be at least 1 real PC and -1 sentinel at the end.
  if (SAN_WARN(atomics.size() < 2 || atomics.back() != -1ul))
    return;
  SAN_LOG("adding atomics: 0x%zx-0x%zx, mod: 0x%zx-0x%zx", atomics[0],
          atomics[atomics.size() - 2], mod.start_pc, mod.end_pc);
  SAN_WARN(atomics[0] < mod.start_pc || atomics[0] >= mod.end_pc ||
           atomics[atomics.size() - 2] < mod.start_pc ||
           atomics[atomics.size() - 2] >= mod.end_pc);
  if (SAN_WARN(mod.atomics.empty()))
    return;

  // Compute the index base and pick a slot.
  AtomicsVector* atomics_slot = nullptr;
  u32 idx_base = 0;
  for (auto& slot : mod.atomics) {
    if (slot.empty()) {
      atomics_slot = &slot;
      break;
    }
    idx_base += slot.size();
  }
  if (SAN_WARN(!atomics_slot))
    return;

  // Compute all MetaFunc::atomic_flat_idx.
  u32 inner_idx = 0;
  for (auto& func : mod.funcs) {
    if (func.atomic_flat_idx != kNoAtomics)
      continue;  // already computed
    const uptr func_start = mod.start_pc + func.offset;
    // Sentinel ensures we stop eventually.
    while (atomics[inner_idx] < func_start)
      inner_idx++;
    if (atomics[inner_idx] < func_start + func.size)
      func.atomic_flat_idx = inner_idx + idx_base;
  }

  *atomics_slot = move(atomics);
}

void AttachAtomics() SAN_REQUIRES(semantic_mtx) {
  sort(pending_atomics->begin(), pending_atomics->end(),
       [](const AtomicsVector& a, const AtomicsVector& b) -> bool {
         return a[0] < b[0];
       });
  // We now have modules and pending atomics sorted.
  // Walk both arrays in parallel to find matches and attach pending atomics
  // to corresponding modules.
  uptr apos = 0;
  uptr mpos = 0;
  for (auto& atomics : *pending_atomics) {
    // There must be at least 1 real PC and -1 sentinel at the end.
    if (SAN_WARN(atomics.size() < 2 || atomics.back() != -1ul))
      continue;
    // Skip non-matching modules.
    while (mpos < modules->size() && (*modules)[mpos].end_pc <= atomics[0])
      mpos++;
    if (mpos == modules->size() || (*modules)[mpos].start_pc > atomics[0]) {
      // We don't yet have the corresponding module, keep atomics for the next
      // round of attaching.
      (*pending_atomics)[apos++] = move(atomics);
      continue;
    }
    AddAtomics((*modules)[mpos], move(atomics));
  }
  SAN_LOG("attached %zu atomics, %zu left", pending_atomics->size() - apos,
          apos);
  // Note: we cannot reset pending_atomics since it will call free and
  // we may be in a signal handler.
  pending_atomics->shrink(apos);
}

// Find the first MetaModule where `pc` is equal or larger than the start_pc of
// the module.
MetaModule* FindFirstMetaModule(uptr pc) SAN_REQUIRES(semantic_mtx) {
  if (modules->empty())
    return nullptr;
  auto mod = upper_bound(
      modules->begin(), modules->end(), pc,
      [](uptr pc, const MetaModule& mod) -> bool { return pc < mod.start_pc; });
  if (mod != modules->begin())
    --mod;
  if (pc < mod->start_pc)
    return nullptr;
  return mod;
}

// Find the MetaModule that contains `pc`, nullptr otherwise.
MetaModule* FindMetaModule(uptr pc) SAN_REQUIRES(semantic_mtx) {
  auto mod = FindFirstMetaModule(pc);
  if (!mod)
    return nullptr;
  if (pc >= mod->end_pc)
    return nullptr;
  return mod;
}

Pair<MetaModule*, MetaFunc*> FindFunc(uptr pc, bool compact = true)
    SAN_REQUIRES(semantic_mtx) {
  if (!modules)
    return {};
  if (!modules_compacted || !modules_sorted) {
    last_module = nullptr;
    last_func = nullptr;
  }
  // Note: we need to compact unsorted modules even if compaction wasn't
  // requested. Otherwise dead modules can interfere with the binary search
  // if a new module was loaded at the address of an unloaded module.
  if (!modules_compacted && (compact || !modules_sorted))
    CompactModules();
  if (!modules_sorted)
    SortModules();
  if (pending_atomics && !pending_atomics->empty())
    AttachAtomics();
  if (modules->empty())
    return {};
  if (last_module && pc >= last_module->start_pc && pc < last_module->end_pc) {
    const u32 offset = static_cast<u32>(pc - last_module->start_pc);
    if (offset >= last_func->offset &&
        offset < last_func->offset + last_func->size)
      return {last_module, last_func};
  }
  auto* mod = FindMetaModule(pc);
  if (!mod)
    return {};
  const u32 offset = static_cast<u32>(pc - mod->start_pc);
  auto func = upper_bound(mod->funcs.begin(), mod->funcs.end(), offset,
                          [](uptr offset, const MetaFunc& func) -> bool {
                            return offset < func.offset;
                          });
  if (func != mod->funcs.begin())
    --func;
  if (offset < func->offset || offset >= func->offset + func->size)
    return {};
  last_module = mod;
  last_func = func;
  return {mod, func};
}
}  // namespace

bool InitSemanticMetadata(SemanticFlags needed) {
  if (SAN_WARN(inited))
    return false;
  inited = true;
  needed_features = needed;
  if (delayed_metadata) {
    for (auto& md : *delayed_metadata)
      md.fn(md.version, md.start, md.end);
    delayed_metadata.reset();
  }
  // Since we cannot deallocate pending_atomics in AttachAtomics,
  // at least free pending_atomics after the initial modules loading.
  Lock lock(semantic_mtx);
  FindFunc(0);
  if (pending_atomics && pending_atomics->empty())
    pending_atomics.reset();
  return true;
}

bool HasSemanticMetadata(SemanticFlags mask) {
  SAN_DCHECK_EQ(needed_features & mask, mask);

  if (IsRuntimeInDSO(reinterpret_cast<uptr>(&HasSemanticMetadata))) {
    // Pretend we have semantic metadata: the runtime is loaded as a DSO, which
    // means the constructors are running before the main binary's constructors.
    // The runtime DSO doesn't have any semantic metadata, which means any tool
    // that checks for existence of semantic metadata will fail to load.
    //
    // As such, let's just pretend that we have semantic metadata, and once the
    // main binary's constructors are running the semantic metadata will be
    // initialized. Until then, we may simply skip analysis of some early
    // functions due to considering them as "uncovered".
    return true;
  }

  return (__atomic_load_n(&covered_features, __ATOMIC_RELAXED) & mask) == mask;
}

bool IsFunctionStart(uptr pc) {
  ScopedAsyncSignalSafe async_signal_safe;
  // Inject episodic spurious failures in debug builds just to ensure we
  // don't have false assumptions that functions must succeed in some contexts.
  TryLock lock(semantic_mtx, FaultInjectLikely());
  if (!lock)
    return false;
  auto [mod, func] = FindFunc(pc);
  return func && mod->start_pc + func->offset == pc;
}

Optional<uptr> IsUARFunctionStart(uptr pc) {
  SAN_DCHECK(needed_features & kSemanticUAR);
  ScopedAsyncSignalSafe async_signal_safe;
  TryLock lock(semantic_mtx, FaultInjectLikely());
  // This function can be used from signal handlers, and it's possible that
  // the signal handler runs while executing __sanitizer_metadata_*()
  // callbacks. Therefore, if the semantic metadata is being updated
  // concurrently, a tool should skip `pc` and try again later.
  if (!lock)
    return {};
  auto [mod, func] = FindFunc(pc);
  if (!func || mod->start_pc + func->offset != pc ||
      !(func->features & kSemanticUAR))
    return {};
  return func->stack_args_size;
}

Optional<bool> IsAtomicPC(uptr pc) {
  SAN_DCHECK(needed_features & kSemanticAtomic);
  ScopedAsyncSignalSafe async_signal_safe;
  TryLock lock(semantic_mtx, FaultInjectLikely());
  if (!lock)
    return {};  // see the comment in IsUARFunctionStart
  auto [mod, func] = FindFunc(pc);
  if (!func || !(func->features & kSemanticAtomic))
    return {};
  const uptr* pc_p = mod->GetAtomicPC(func->atomic_flat_idx);
  if (!pc_p)
    return false;
  // Note: we don't need to check the size, since we added sentinel at the end.
  for (; *pc_p <= pc; pc_p++) {
    if (*pc_p == pc)
      return true;
  }
  return false;
}

void DumpSemanticMetadata() {
#if GWPSAN_DEBUG
  Lock lock(semantic_mtx);
  if (!modules) {
    Printf("no semantic metadata present\n");
    return;
  }
  for (const auto& mod : *modules) {
    ModuleInfo info = {
        .name = "???",
        .start_address = mod.start_pc,
        .end_address = mod.end_pc,
        .pc_offset = 0,
    };
    if (const auto* infop = FindModule(mod.start_pc))
      info = *infop;
    uptr atomics = mod.atomics.size();
    if (atomics)
      atomics--;  // account for the sentinel
    Printf("module 0x%zx-0x%zx funcs:%zu atomics:%zu %s\n", info.start_address,
           info.end_address, mod.funcs.size(), atomics, info.name);
    for (const auto& func : mod.funcs) {
      char name[256];
      Symbolize(func.offset + mod.start_pc, name, sizeof(name), false);
      uptr off = func.offset + mod.start_pc - info.start_address;
      const char* atomics = func.features & kSemanticAtomic ? " atomics" : "";
      const char* uar = func.features & kSemanticUAR ? " uar" : "";
      Printf("  func 0x%zx-0x%zx(%4u) features:%s%s args:%u %s\n", off,
             off + func.size, func.size, atomics, uar, func.stack_args_size,
             name);
      uptr func_end = mod.start_pc + func.offset + func.size;
      for (const uptr* pc_p = mod.GetAtomicPC(func.atomic_flat_idx);
           pc_p && *pc_p < func_end; pc_p++)
        Printf("    atomic 0x%zx\n", *pc_p - info.start_address);
    }
  }
#else   // #if GWPSAN_DEBUG
  Printf("metadata dumper isn't compiled it, rebuild with -DGWPSAN_DEBUG\n");
#endif  // #if GWPSAN_DEBUG
}

SemanticMetadataScopedFork::SemanticMetadataScopedFork()
    SAN_ACQUIRE(semantic_mtx) {
  semantic_mtx.Lock();
}

SemanticMetadataScopedFork::~SemanticMetadataScopedFork()
    SAN_RELEASE(semantic_mtx) {
  semantic_mtx.Unlock();
}
}  // namespace gwpsan

using namespace gwpsan;

// Compiler ABI v1 (-fsanitize-metadata)
namespace {
constexpr u32 kVersionPtrSizeRel = (1u << 16);  // offsets are pointer-sized
constexpr u32 kFeatureMaskAtomics = (1u << 0);  // atomics are covered
constexpr u32 kFeatureMaskUAR = (1u << 1);      // function is suitable for UAR
constexpr u32 kFeatureMaskUARHasSize =
    (1u << 2);  // function is suitable for UAR (has stack args size)

constexpr u32 GetVersionBase(u32 version) {
  return version & 0xffff;
}

constexpr SemanticFlags FeatureMaskToSemanticFlags(u32 features) {
  SemanticFlags sf = 0;
  if (features & kFeatureMaskAtomics)
    sf |= kSemanticAtomic;
  if (features & kFeatureMaskUAR)
    sf |= kSemanticUAR;
  return sf;
}

template <typename T>
T Consume(const char*& pos, const char* end) {
  T v;
  // Need to use memcpy(), because metadata may be packed such that `pos` is not
  // always T aligned. Use inline memcpy because we know the size is small.
  __builtin_memcpy_inline(&v, pos, sizeof(T));
  pos += sizeof(T);
  SAN_DCHECK_LE(pos, end);
  return v;
}

u64 ConsumeULEB128(const char*& pos, const char* end) {
  u64 val = 0;
  int shift = 0;
  u8 cur;
  do {
    cur = *pos++;
    val |= u64{cur & 0x7fu} << shift;
    shift += 7;
  } while (cur & 0x80);
  SAN_DCHECK_LT(shift, 64);
  SAN_DCHECK_LE(pos, end);
  return val;
}

uptr ConsumeRelativePC(const char*& pos, const char* end, u32 version) {
  const uptr base = reinterpret_cast<uptr>(pos);
  const sptr offset = (version & kVersionPtrSizeRel) ? Consume<sptr>(pos, end)
                                                     : Consume<s32>(pos, end);

  // offset of 0 indicates we're reading into section padding.
  if (!offset)
    return 0;

  return base + offset;
}

constexpr uptr SizeofRelativePC(u32 version) {
  return (version & kVersionPtrSizeRel) ? sizeof(sptr) : sizeof(s32);
}

template <typename F>
void ParseCoveredInfo(u32 version, const char* start, const char* end,
                      const F& f) {
  // Entry: [ <offset: 4 or sizeof(void*) bytes>
  //        | <size: uleb128>
  //        | <feature: uleb128>
  //        | <stack_args_size: uleb128> present if kFeatureMaskUARHasSize ]
  //
  // Note: the section is rounded up to 8 bytes. If we just check "entry < end"
  // we can start parsing the last padding bytes.
  for (const char* entry = start; entry + SizeofRelativePC(version) <= end;) {
    const uptr func_start = ConsumeRelativePC(entry, end, version);
    if (!func_start)
      break;  // Started to read into padding; stop.

    u32 size, features, stack_args_size;
    if (GetVersionBase(version) >= 2) {
      size = ConsumeULEB128(entry, end);
      features = ConsumeULEB128(entry, end);
      stack_args_size =
          (features & kFeatureMaskUARHasSize) ? ConsumeULEB128(entry, end) : 0;
    } else {
      size = Consume<u32>(entry, end);
      features = Consume<u32>(entry, end);
      stack_args_size =
          (features & kFeatureMaskUAR) ? Consume<u32>(entry, end) : 0;
    }
    f(func_start, size, FeatureMaskToSemanticFlags(features), stack_args_size);
  }
}

bool SkipMetadataAdd(SemanticFlags needed, LoadFunc fn, u32 version,
                     const char* start, const char* end) {
  if (SAN_WARN(GetVersionBase(version) > 2))
    return true;
  // If we already know what features we need, skip the metadata callback
  // if we don't need the current feature.
  if (inited)
    return !(needed_features & needed);
  // Otherwise, postpone the callback.
  // Note: we must not touch (page in) the metadata itself.
  if (!delayed_metadata)
    delayed_metadata.emplace();
  delayed_metadata->emplace_back(fn, version, start, end);
  return true;
}

bool SkipMetadataDel(SemanticFlags needed, u32 version, const char* start) {
  if (SAN_WARN(GetVersionBase(version) > 2))
    return true;
  if (inited)
    return !(needed_features & needed);
  // Note: we can't postpone del callback since the metadata will be unmapped
  // after it, instead we find the corresponding add callback info and make
  // it effectively a no-op when it will be processed later.
  if (delayed_metadata) {
    for (auto& md : *delayed_metadata) {
      if (md.start == start)
        md.start = md.end = nullptr;
    }
  }
  return true;
}
}  // namespace

SAN_INTERFACE void __sanitizer_metadata_covered_add(u32 version,
                                                    const char* start,
                                                    const char* end) {
  SAN_LOG("covered metadata (v%u) add %p-%p", version, start, end);
  if (SkipMetadataAdd(kSemanticAll, __sanitizer_metadata_covered_add, version,
                      start, end))
    return;
  uptr count = 0;
  uptr min_addr = static_cast<uptr>(-1);
  uptr max_addr = 0;
  SemanticFlags combined_features = 0;

  // Pass 1: Parse metadata to determine min_addr used to calculate offsets
  // below.
  ParseCoveredInfo(version, start, end,
                   [&](uptr start, u32 size, SemanticFlags features, u32) {
                     count++;
                     min_addr = min(min_addr, start);
                     max_addr = max(max_addr, start + size);
                     combined_features |= features;
                     metric_metadata_covered.LossyAdd(1);
                     if (features & kSemanticAtomic)
                       metric_metadata_covered_atomics.LossyAdd(1);
                     if (features & kSemanticUAR)
                       metric_metadata_covered_uar.LossyAdd(1);
                   });
  if (!count)
    return;
  __atomic_fetch_or(&covered_features, combined_features, __ATOMIC_RELAXED);

  MetaModule mod;
  mod.funcs.reserve(count);
  mod.start_pc = min_addr;
  mod.end_pc = max_addr;

  // Pass 2: Compute and store offsets of function PCs.
  ParseCoveredInfo(
      version, start, end,
      [&](uptr start, u32 size, SemanticFlags features, u32 stack_args_size) {
        const uptr offset = start - min_addr;
        if (SAN_WARN(offset != static_cast<u32>(offset)))
          return;
        mod.funcs.emplace_back(static_cast<u32>(offset), size, stack_args_size,
                               features, kNoAtomics);
      });
  auto pred = [](const MetaFunc& a, const MetaFunc& b) -> bool {
    return a.offset < b.offset;
  };
  // Frequently sorted, but compiler/linker do not guarantee that.
  if (!is_sorted(mod.funcs.begin(), mod.funcs.end(), pred))
    sort(mod.funcs.begin(), mod.funcs.end(), pred);

  // Append to global list of modules.
  Lock lock(semantic_mtx);
  if (!modules)
    modules.emplace();

  auto funcs_add_offset = [](MallocVector<MetaFunc>& funcs, uptr offset_delta) {
    for (auto& func : funcs) {
      const uptr new_offset = offset_delta + func.offset;
      if (SAN_WARN(new_offset != static_cast<u32>(new_offset)))
        return;
      func.offset = static_cast<u32>(new_offset);
    }
  };
  // Find overlapping module and merge new covered metadata into it. This is
  // possible if a module was linked from TUs that have sanitizer metadata of
  // different versions. Multi-version sanitizer metadata usage requires this
  // LLVM fix commit: https://github.com/llvm/llvm-project/commit/f5b9e11eb8ad
  auto* overlap_mod = FindFirstMetaModule(mod.end_pc);
  if (overlap_mod && mod.start_pc < overlap_mod->end_pc) {
    SAN_LOG("found overlapping module 0x%zx-0x%zx", overlap_mod->start_pc,
            overlap_mod->end_pc);
    overlap_mod->end_pc = max(overlap_mod->end_pc, mod.end_pc);
    if (mod.start_pc < overlap_mod->start_pc) {
      // Adjust all pre-existing function offsets to the new start_pc.
      funcs_add_offset(overlap_mod->funcs,
                       overlap_mod->start_pc - mod.start_pc);
      overlap_mod->start_pc = mod.start_pc;
    } else {
      // Adjust the new function offsets to the old start_pc.
      funcs_add_offset(mod.funcs, mod.start_pc - overlap_mod->start_pc);
    }
    // Merge functions. We assume that there are no duplicate functions.
    overlap_mod->funcs.reserve(overlap_mod->funcs.size() + mod.funcs.size());
    for (auto& func : mod.funcs)
      overlap_mod->funcs.emplace_back(func);
    // Sort merged functions; unlikely to still be sorted.
    sort(overlap_mod->funcs.begin(), overlap_mod->funcs.end(), pred);
    // Reserve one more atomics slot.
    overlap_mod->atomics.emplace_back();
  } else {
    mod.atomics.emplace_back();
    modules->emplace_back(move(mod));
  }
  modules_sorted = false;

  SAN_LOG("loaded %zu covered metadata entries from %p-%p (0x%zx-0x%zx %s)",
          count, start, end, min_addr, max_addr, [ctor_pc = SAN_CALLER_PC()] {
            if (const auto* mod = FindModule(ctor_pc))
              return mod->name;
            return "unknown";
          }());
}

SAN_INTERFACE void __sanitizer_metadata_covered_del(u32 version,
                                                    const char* start,
                                                    const char* end) {
  SAN_LOG("covered metadata (v%u) del %p-%p", version, start, end);
  if (SkipMetadataDel(kSemanticAll, version, start))
    return;
  if (end - start < SizeofRelativePC(version))
    return;
  Lock lock(semantic_mtx);
  const char* entry = start;  // advanced by ConsumeRelativePC()
  auto [mod, _] = FindFunc(ConsumeRelativePC(entry, end, version), false);
  if (!mod) {
    // This is possible with multi-version semantic metadata, where we can get
    // multiple delete callbacks for the same module.
    return;
  }
  // All modules (potentially thousands) are unloaded when the program exits,
  // so we avoid compacting them eagerly to avoid quadratic work.
  // Instead we just mark the module as unloaded and delay compaction.
  mod->end_pc = mod->start_pc;
  mod->funcs.reset();
  mod->atomics.reset();
  modules_compacted = false;

  SAN_LOG("unloaded covered metadata from %p-%p", start, end);
}

SAN_INTERFACE void __sanitizer_metadata_atomics_add(u32 version,
                                                    const char* start,
                                                    const char* end) {
  SAN_LOG("atomics metadata (v%u) add %p-%p", version, start, end);
  if (SkipMetadataAdd(kSemanticAtomic, __sanitizer_metadata_atomics_add,
                      version, start, end))
    return;
  // Entry: [ <offset: 4 or sizeof(void*) bytes> ]
  const uptr entry_size = (version & kVersionPtrSizeRel) ? sizeof(void*) : 4;
  AtomicsVector atomics;
  atomics.reserve((end - start) / entry_size + 1);
  for (const char* entry = start; entry < end;) {
    if (const uptr pc = ConsumeRelativePC(entry, end, version))
      atomics.emplace_back(pc);
  }
  if (atomics.empty())
    return;
  metric_metadata_atomics.LossyAdd(atomics.size());
  // Frequently sorted, but compiler/linker do not guarantee that.
  if (!is_sorted(atomics.begin(), atomics.end()))
    sort(atomics.begin(), atomics.end());
  atomics.emplace_back(-1ul);  // sentinel for search
  Lock lock(semantic_mtx);
  // Atomics and covered callbacks are unordered, moreover there can be
  // concurrent dlopen's and metadata queries that sort modules.
  // As a result it's very hard to match covered and atomics metadata
  // during loading with the current compiler interface, so we postpone
  // matching until we sort modules.
  if (!pending_atomics)
    pending_atomics.emplace();
  pending_atomics->emplace_back(move(atomics));
  // Re-request sorting in the case modules were sorted in between covered
  // and atomics callbacks.
  modules_sorted = false;
}

SAN_INTERFACE void __sanitizer_metadata_atomics_del(u32 version,
                                                    const char* start,
                                                    const char* end) {
  SAN_LOG("atomics metadata (v%u) del %p-%p", version, start, end);
  if (SkipMetadataDel(kSemanticAtomic, version, start))
    return;

  // Atomics data is dropped with the module in the covered callback.
}
