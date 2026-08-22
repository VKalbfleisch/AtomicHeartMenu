// SPDX-License-Identifier: GPL-3.0-or-later
//
// Atomic Heart Menu - internal mod menu for single-player Atomic Heart.
// Copyright (C) 2026 Skorchekd
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. Distributed WITHOUT ANY WARRANTY. See the LICENSE file for details.
//
// Additional terms (GPLv3 Section 7): you must preserve attribution to the author
// (Skorchekd) and to Dumper-7 (Encryqed), MinHook (Tsuda Kageyu), and Dear ImGui
// (ocornut). See LICENSE and NOTICE. Forks must stay GPL-3.0-or-later and open.
#include "memory.h"
#include <Windows.h>

// ===========================================================================
//  VirtualQuery region cache  (the menu's single biggest perf lever)
// ---------------------------------------------------------------------------
//  Mem::IsReadable was the hottest function in the whole menu: it ran a
//  VirtualQuery -- a kernel transition -- on EVERY guarded read. A cold GObjects
//  resolve walks ~90k-300k objects, each costing several IsReadable calls, so a
//  single FindObject was MILLIONS of syscalls. The runtime log showed exactly
//  this: a cold FindObject took 650-900ms, the name-index build ~4s, a full
//  object dump ~55s -- effectively ALL of it spent inside VirtualQuery, not in
//  the iteration itself.
//
//  A single VirtualQuery already describes a whole committed RUN of same-protect
//  pages: [BaseAddress, BaseAddress + RegionSize). We cache those runs per thread
//  and answer later in-range queries with a couple of compares, collapsing the
//  syscall storm to a handful. Scans hammer a small set of large heap segments, so
//  even a tiny cache gets a ~99% hit rate -> the same scans drop by more than an
//  order of magnitude.
//
//  SAFETY MODEL  (why a cache here cannot crash the game):
//    * POSITIVE-ONLY: we cache committed + non-guard runs that already answered
//      the query "yes". A negative answer is NEVER cached, so we can never
//      wrongly report a live address as unreadable for longer than the single
//      call that saw it.
//    * The only staleness window is the game FREEING a run we cached within the
//      TTL, after which a read into it could fault. That fault is
//      already the menu's normal failure mode for a wrong offset and is caught by
//      the /EHa try/catch firewalls around every scan and around TickImpl (see
//      CMakeLists /EHa + the per-object guards in the scan loops) -> it degrades
//      to a skipped object, never a crash. The TTL just bounds the window.
//    * THREAD-LOCAL: no locks. VirtualQuery results are process-wide, so each
//      worker / render / index thread simply keeps its own hot view.
// ===========================================================================
namespace
{
    struct CachedRegion { uintptr_t base; uintptr_t end; };

    constexpr int       kRegionSlots = 32;   // hot heap segments tracked per thread
    constexpr ULONGLONG kRegionTtlMs = 250;  // bound staleness to ~a few frames

    // One cache per question, never shared: readable is a superset of executable,
    // so a shared cache filled by readable-only runs would answer "yes" to an
    // executable query for a plain data page.
    struct RegionCache
    {
        CachedRegion slot[kRegionSlots];
        int          count;
        int          next;      // round-robin eviction cursor
        ULONGLONG    stampMs;
    };

    thread_local RegionCache tl_readable{};
    thread_local RegionCache tl_executable{};

    inline void RegionFlushIfStale(RegionCache& c)
    {
        ULONGLONG now = GetTickCount64();
        if (now - c.stampMs > kRegionTtlMs)
        {
            c.count   = 0;
            c.next    = 0;
            c.stampMs = now;
        }
    }

    inline bool RegionContains(const RegionCache& c, uintptr_t addr, size_t size)
    {
        for (int i = 0; i < c.count; ++i)
            if (addr >= c.slot[i].base && (addr + size) <= c.slot[i].end)
                return true;
        return false;
    }

    inline void RegionStore(RegionCache& c, uintptr_t base, uintptr_t end)
    {
        for (int i = 0; i < c.count; ++i)
            if (c.slot[i].base == base) { c.slot[i].end = end; return; }
        if (c.count < kRegionSlots)
            c.slot[c.count++] = { base, end };
        else
        {
            c.slot[c.next] = { base, end };
            c.next = (c.next + 1) % kRegionSlots;
        }
    }

    bool QueryRegion(const void* p, size_t size, DWORD wanted, RegionCache& cache)
    {
        if (!p || size == 0) return false;

        auto addr = reinterpret_cast<uintptr_t>(p);
        // reject the null page and non-canonical / kernel-space addresses
        if (addr < 0x10000 || addr > 0x7FFFFFFFFFFFull) return false;

        // Fast path: a recently-seen run of this kind already covers the range.
        RegionFlushIfStale(cache);
        if (RegionContains(cache, addr, size))
            return true;

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (!(mbi.Protect & wanted)) return false;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;

        // make sure the whole requested range sits inside this committed region
        auto regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        auto regionEnd   = regionStart + mbi.RegionSize;

        // Positive-only -- see the safety note above.
        RegionStore(cache, regionStart, regionEnd);

        return (addr + size) <= regionEnd;
    }
}

bool Mem::IsReadable(const void* p, size_t size)
{
    constexpr DWORD readable =
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return QueryRegion(p, size, readable, tl_readable);
}

bool Mem::IsExecutable(const void* p, size_t size)
{
    // PAGE_EXECUTE alone is deliberately included: DEP permits the call even
    // though we could not read the bytes there. Only the absence of every execute
    // bit faults.
    constexpr DWORD executable =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return QueryRegion(p, size, executable, tl_executable);
}

bool Mem::LooksLikePtr(const void* p)
{
    auto addr = reinterpret_cast<uintptr_t>(p);
    if (addr & 0x7) return false;            // UObjects are 8/16-byte aligned
    return Mem::IsReadable(p, sizeof(void*));
}
