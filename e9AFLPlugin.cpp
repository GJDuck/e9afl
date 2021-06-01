/*
 *        ___    _    _____ _     
 *   ___ / _ \  / \  |  ___| |    
 *  / _ \ (_) |/ _ \ | |_  | |    
 * |  __/\__, / ___ \|  _| | |___ 
 *  \___|  /_/_/   \_\_|   |_____|
 * 
 * Copyright (C) 2021 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cassert>

#include <initializer_list>
#include <map>
#include <sstream>
#include <string>
#include <set>
#include <vector>

#include "e9plugin.h"

using namespace e9frontend;

#include "e9cfg.cpp"

#define AREA_BASE   0x200000
#define AREA_SIZE   ((size_t)1 << 16)

/*
 * Options.
 */
enum Option
{
    OPTION_NEVER,
    OPTION_DEFAULT,
    OPTION_ALWAYS
};
static Option option_debug      = OPTION_DEFAULT;
static Option option_instrument = OPTION_DEFAULT;
static Option option_Oselect    = OPTION_DEFAULT;
static Option option_Oblock     = OPTION_DEFAULT;

static Option parseOption(const char *str)
{
    if (strcmp(str, "never") == 0)
        return OPTION_NEVER;
    if (strcmp(str, "default") == 0)
        return OPTION_DEFAULT;
    if (strcmp(str, "always") == 0)
        return OPTION_ALWAYS;
    error("bad option value \"%s\"; expected one of {\"never\", \"default\", "
        "\"always\"}", str);
}

/*
 * CFG
 */
struct BB
{
    std::vector<intptr_t> preds;    // Predecessor BBs
    std::vector<intptr_t> succs;    // Successor BBs
    intptr_t instrument = -1;       // Instrumentation point
    bool optimized      = false;    // Optimize block?
    bool bad            = false;    // Bad block?
};
typedef std::map<intptr_t, BB> CFG;
#define BB_INDIRECT     (-1)

/*
 * To compile:
 *      $ g++ -std=c++11 -fPIC -shared -o e9afl.so -O2 e9afl.cpp \
 *          -I .
 */

/*
 * All instrumentation points.
 */
static std::set<intptr_t> instrument;

/*
 * Initialization.
 */
extern void *e9_plugin_init_v1(FILE *out, const ELF *elf)
{
    // Make seed depend on filename.
    unsigned seed = 0;
    const char *filename = getELFFilename(elf);
    for (int i = 0; filename[i] != '\0'; i++)
        seed = 101 * seed + (unsigned)filename[i];
    srand(seed);

    const int32_t stack_adjust = 0x4000;
    const int32_t afl_rt_ptr   = 0x50000000;
    const int32_t afl_area_ptr = AREA_BASE;

    // Reserve memory used by the afl_area_ptr:
    sendReserveMessage(out, afl_area_ptr, AREA_SIZE, /*absolute=*/true);

    const char *str = nullptr;
    std::string option_path(".");
    if ((str = getenv("E9AFL_DEBUG")) != nullptr)
        option_debug = parseOption(str);
    if ((str = getenv("E9AFL_INSTRUMENT")) != nullptr)
        option_instrument = parseOption(str);
    if ((str = getenv("E9AFL_OBLOCK")) != nullptr)
        option_Oblock = parseOption(str);
    if ((str = getenv("E9AFL_OSELECT")) != nullptr)
        option_Oselect = parseOption(str);
    if ((str = getenv("E9AFL_PATH")) != nullptr)
        option_path = str;
 
    if (option_instrument == OPTION_NEVER)
        return nullptr;
    if (option_Oblock == OPTION_ALWAYS)
        warning("always removing AFL instrumentation for bad blocks; coverage "
            "may be incomplete");

    // Send the AFL runtime (if not shared object):
    std::string path(option_path);
    path += "/afl-rt";
    const ELF *rt = parseELF(path.c_str(), afl_rt_ptr);
    sendELFFileMessage(out, rt);

    // Send the AFL instrumentation:
    //
    // Save state:
    //
    // lea -0x4000(%rsp),%rsp
    // push %rax
    // seto %al
    // lahf
    // push %rax
    //
    std::stringstream code;
    code << 0x48 << ',' << 0x8d << ',' << 0xa4 << ',' << 0x24 << ','
         << "{\"int32\":" << -stack_adjust << "},";
    code << 0x50 << ',';
    code << 0x0f << ',' << 0x90 << ',' << 0xc0 << ',';
    code << 0x9f << ',';
    code << 0x50 << ',';

    // AFL instrumentation:
    //
    // mov %fs:0x48,%eax                    // mov prev_loc,%eax
    // xor $curr_loc,%eax
    // incb afl_area_ptr(%eax)
    // movl $(curr_loc>>1),%fs:0x48         // mov (curr_loc>>1),prev_loc
    //
    code << 0x64 << ',' << 0x8b << ',' << 0x04 << ',' << 0x25 << ','
         << 0x48 << ',' << 0x00 << ',' << 0x00 << ',' << 0x00 << ',';
    code << 0x35 << ',' << "\"$curr_loc\"" << ',';
    code << 0x67 << ',' << 0xfe << ',' << 0x80 << ','
         << "{\"int32\":" << afl_area_ptr << "},";
    code << 0x64 << ',' << 0xc7 << ',' << 0x04 << ',' << 0x25 << ','
         << 0x48 << ',' << 0x00 << ',' << 0x00 << ',' << 0x00 << ','
         << "\"$curr_loc_1\"" << ',';
 
    // Restore state:
    //
    // pop %rax
    // add $0x7f,%al
    // sahf
    // pop %rax  
    // lea 0x4000(%rsp),%rsp
    // $instruction
    // $continue
    //
    code << 0x58 << ',';
    code << 0x04 << ',' << 0x7f << ',';
    code << 0x9e << ',';
    code << 0x58 << ',';
    code << 0x48 << ',' << 0x8d << ',' << 0xa4 << ',' << 0x24 << ','
         << "{\"int32\":" << stack_adjust << "},";
    code << "\"$instruction\",\"$continue\"";

    sendTrampolineMessage(out, "afl", code.str().c_str());

    return nullptr;
}

/*
 * Add a predecessor block.
 */
static void addPredecessor(intptr_t pred, intptr_t succ,
    const Targets &targets, CFG &cfg)
{
    auto i = targets.lower_bound(succ);
    if (i == targets.end())
        return;
    succ = i->first;
    auto j = cfg.find(succ);
    if (j == cfg.end())
    {
        BB empty;
        auto r = cfg.insert({succ, empty});
        j = r.first;
    }
    j->second.preds.push_back(pred);
}

/*
 * Add a successor block.
 */
static void addSuccessor(intptr_t pred, intptr_t succ,
    const Targets &targets, CFG &cfg)
{
    auto i = targets.find(pred);
    if (i == targets.end())
        return;
    auto j = cfg.find(pred);
    if (j == cfg.end())
    {
        BB empty;
        auto r = cfg.insert({pred, empty});
        j = r.first;
    }
    j->second.succs.push_back(succ);
}

/*
 * Build the CFG from the set of jump targets.
 */
static void buildCFG(const ELF *elf, const Instr *Is, size_t size,
    const Targets &targets, CFG &cfg)
{
    for (const auto &entry: targets)
    {
        intptr_t target = entry.first, bb = target;
        TargetKind kind = entry.second;

        size_t i = findInstr(Is, size, target);
        if (i >= size)
            continue;

        if (kind != TARGET_DIRECT)
            addPredecessor(BB_INDIRECT, bb, targets, cfg);

        const Instr *I = Is + i;

        for (++i; i < size; i++)
        {
            InstrInfo info0, *info = &info0;
            getInstrInfo(elf, I, info);
            bool end = false;
            intptr_t target = -1, next = -1;
            switch (info->mnemonic)
            {
                case MNEMONIC_RET:
                    end = true;
                    break;
                case MNEMONIC_JMP:
                    end = true;
                    // Fallthrough:
                case MNEMONIC_CALL:
                    if (info->op[0].type == OPTYPE_IMM)
                        target = (intptr_t)info->address +
                            (intptr_t)info->size + (intptr_t)info->op[0].imm;
                    break;
                case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
                case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
                case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
                case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
                case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
                case MNEMONIC_JG:
                    end = true;
                    next = (intptr_t)info->address + (intptr_t)info->size;
                    target = next + (intptr_t)info->op[0].imm;
                    break;
                default:
                    break;
            }
            if (target > 0x0)
                addPredecessor(bb, target, targets, cfg);
            if (next > 0x0)
                addPredecessor(bb, next, targets, cfg);
            if (end)
            {
                if (target > 0)
                    addSuccessor(bb, target, targets, cfg);
                if (next > 0)
                    addSuccessor(bb, next, targets, cfg);
                if (!(target > 0 || next > 0))
                    addSuccessor(bb, BB_INDIRECT, targets, cfg);
                break;
            }
            const Instr *J = I+1;
            if (I->address + I->size != J->address)
                break;
            if (targets.find(J->address) != targets.end())
            {
                // Fallthrough:
                addPredecessor(bb, J->address, targets, cfg);
                addSuccessor(bb, J->address, targets, cfg);
                break;
            }
            I = J;
        }
    }
}

/*
 * Attempt to optimize away a bad block.
 */
typedef std::map<BB *, BB *> Paths;
static void optimizePaths(CFG &cfg, BB *pred_bb, BB *succ_bb, Paths &paths)
{
    auto i = paths.find(succ_bb);
    if (i != paths.end())
    {
        // Multiple paths to succ_bb;
        if (pred_bb != nullptr)
            pred_bb->optimized = false;
        else if (i->second != nullptr)
            i->second->optimized = false;
        return;
    }
    paths.insert({succ_bb, pred_bb});
    if (succ_bb == nullptr || !succ_bb->optimized)
        return;

    pred_bb = succ_bb;
    for (auto succ: succ_bb->succs)
    {
        auto i = cfg.find(succ);
        succ_bb = (i == cfg.end()? nullptr: &i->second);
        optimizePaths(cfg, pred_bb, succ_bb, paths);
    }
}
static void optimizeBlock(CFG &cfg, intptr_t entry, BB &bb)
{
    if (bb.optimized)
        return;
    Paths paths;
    for (auto succ: bb.succs)
    {
        auto i = cfg.find(succ);
        BB *succ_bb = (i == cfg.end()? nullptr: &i->second);
        optimizePaths(cfg, nullptr, succ_bb, paths);
    }
}

/*
 * Verify the optimization is correct (for debugging).
 */
static void verify(CFG &cfg, const std::map<intptr_t, unsigned> &bbs, BB *bb,
    std::set<BB *> &seen)
{
    for (auto succ: bb->succs)
    {
        auto i = cfg.find(succ);
        BB *succ_bb = (i == cfg.end()? nullptr: &i->second);
        if (succ_bb == nullptr)
            fprintf(stderr, " indirect");
        else
        {
            auto j = bbs.find(succ);
            fprintf(stderr, " BB_%u", j->second);
        }
        auto r = seen.insert(succ_bb);
        if (!r.second)
        {
            putc('\n', stderr);
            error("multiple non-instrumented paths detected");
        }
        if (succ_bb != nullptr && succ_bb->instrument < 0)
            verify(cfg, bbs, succ_bb, seen);
    }
}
static void verify(CFG &cfg, const std::map<intptr_t, unsigned> &bbs)
{
    putc('\n', stderr);
    for (auto &entry: cfg)
    {
        auto i = bbs.find(entry.first);
        fprintf(stderr, "\33[32mVERIFY\33[0m BB_%u:", i->second);
        std::set<BB *> seen;
        verify(cfg, bbs, &entry.second, seen);
        putc('\n', stderr);
    }
    putc('\n', stderr);
}

/*
 * Calculate all instrumentation points.
 */
static void calcInstrumentPoints(const ELF *elf, const Instr *Is, size_t size,
    Targets &targets, std::set<intptr_t> &instrument)
{
    // Step #1: build the CFG:
    CFG cfg;
    buildCFG(elf, Is, size, targets, cfg);

    // Step #2: find all instrumentation-points/bad-blocks
    for (const auto &entry: targets)
    {
        intptr_t target = entry.first, bb = target;
        TargetKind kind = entry.second;

        size_t i = findInstr(Is, size, target);
        if (i >= size)
            continue;
        const Instr *I = Is + i;

        uint8_t target_size = I->size;
        for (++i; option_Oselect != OPTION_NEVER && i < size &&
                target_size < /*sizeof(jmpq)=*/5; i++)
        {
            InstrInfo info0, *info = &info0;
            getInstrInfo(elf, I, info);
            bool end = false;
            switch (info->mnemonic)
            {
                case MNEMONIC_RET:
                case MNEMONIC_CALL:
                case MNEMONIC_JMP:
                case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
                case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
                case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
                case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
                case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
                case MNEMONIC_JG:
                    end = true;
                    break;
                default:
                    break;
            }
            if (end)
                break;
            const Instr *J = I+1;
            if (I->address + I->size != J->address)
                break;
            if (targets.find(J->address) != targets.end())
                break;
            if (J->size > target_size)
            {
                target      = J->address;
                target_size = J->size;
            }
            I = J;
        }
        auto j = cfg.find(bb);
        assert(j != cfg.end());
        j->second.instrument = target;
        j->second.bad        = (target_size < /*sizeof(jmpq)=*/5);
        j->second.optimized  =
            (option_Oblock != OPTION_NEVER && j->second.bad &&
                kind == TARGET_DIRECT);
    }

    // Step #3: Optimize away bad blocks:
    if (option_Oblock == OPTION_DEFAULT)
        for (auto &entry: cfg)
            optimizeBlock(cfg, entry.first, entry.second);

    // Step #4: Collect final instrumentation points.
    for (auto &entry: cfg)
    {
        if (!entry.second.optimized)
            instrument.insert(entry.second.instrument);
    }

    // Setp #5: Print debugging information (if necessary)
    std::map<intptr_t, unsigned> bbs;
    if (option_debug == OPTION_ALWAYS)
    {
        unsigned bb = 0;
        for (const auto &entry: targets)
            bbs.insert({entry.first, bb++});
    }
    for (size_t i = 0; (option_debug == OPTION_ALWAYS) && i < size; i++)
    {
        InstrInfo I0, *I = &I0;
        getInstrInfo(elf, Is + i, I);

        auto j = cfg.find(I->address);
        if (j != cfg.end())
        {
            auto l = bbs.find(I->address);
            fprintf(stderr, "\n# \33[32mBB_%u\33[0m%s%s\n", l->second,
                (j->second.bad? " [\33[31mBAD\33[0m]": ""),
                (j->second.bad && !j->second.optimized?
                    " [\33[31mUNOPTIMIZED\33[0m]": ""));
            fprintf(stderr, "# preds = ");
            int count = 0;
            for (auto pred: j->second.preds)
            {
                if (count++ != 0)
                    putc(',', stderr);
                if (pred == BB_INDIRECT)
                {
                    fprintf(stderr, "indirect");
                    continue;
                }
                auto l = bbs.find(pred);
                fprintf(stderr, "BB_%u", l->second);
            }
            fprintf(stderr, "\n# succs = ");
            count = 0;
            for (auto pred: j->second.succs)
            {
                if (count++ != 0)
                    putc(',', stderr);
                if (pred == BB_INDIRECT)
                {
                    fprintf(stderr, "indirect");
                    continue;
                }
                auto l = bbs.find(pred);
                fprintf(stderr, "BB_%u", l->second);
            }
            putc('\n', stderr);
        }
        if (instrument.find(I->address) != instrument.end())
            fprintf(stderr, "%lx: \33[33m%s\33[0m\n", I->address,
                I->string.instr);
        else
            fprintf(stderr, "%lx: %s\n", I->address, I->string.instr);
    }
    if (option_debug == OPTION_ALWAYS)
        verify(cfg, bbs);
}

/*
 * Events.
 */
extern void e9_plugin_event_v1(FILE *out, const ELF *elf,
    const Instr *Is, size_t size, Event event, void *context)
{
    switch (event)
    {
        case EVENT_DISASSEMBLY_COMPLETE:
        {
            Targets targets;
            CFGAnalysis(elf, Is, size, targets);
            calcInstrumentPoints(elf, Is, size, targets, instrument);
            break;
        }
        default:
            break;
    }
}

/*
 * Matching.  Return `true' iff we should instrument this instruction.
 */
extern intptr_t e9_plugin_match_v1(FILE *out, const ELF *elf,
    const Instr *Is, size_t size, size_t idx, const InstrInfo *info,
    void *context)
{
    return (instrument.find(info->address) != instrument.end());
}

/*
 * Patching.
 */
extern void e9_plugin_patch_v1(FILE *out, const ELF *elf,
    const Instr *Is, size_t size, size_t idx, const InstrInfo *info,
    void *context)
{
    if (option_instrument == OPTION_NEVER)
        return;
    if (instrument.find(info->address) == instrument.end())
        return;

    Metadata metadata[3];
    int32_t curr_loc = rand() & 0xFFFF;

    metadata[0].name = "curr_loc";
    std::string buf;
    buf += "{\"int32\":";
    buf += std::to_string(curr_loc);
    buf += '}';
    metadata[0].data = buf.c_str();

    metadata[1].name = "curr_loc_1";
    std::string buf_1;
    buf_1 += "{\"int32\":";
    buf_1 += std::to_string(curr_loc >> 1);
    buf_1 += '}';
    metadata[1].data = buf_1.c_str();

    metadata[2].name = nullptr;
    metadata[2].data = nullptr;

    sendPatchMessage(out, "afl", info->offset, metadata);
}

