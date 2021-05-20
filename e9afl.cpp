/*
 *        ___    _    _____ _     
 *   ___ / _ \  / \  |  ___| |    
 *  / _ \ (_) |/ _ \ | |_  | |    
 * |  __/\__, / ___ \|  _| | |___ 
 *  \___|  /_/_/   \_\_|   |_____|
 * 
 * Copyright (C) 2020 National University of Singapore
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

bool option_debug         = false;
bool option_no_instrument = false;

/*
 * To compile:
 *      $ g++ -std=c++11 -fPIC -shared -o e9afl.so -O2 e9afl.cpp \
 *          -I .
 */

/*
 * All jump targets.
 */
static std::set<intptr_t> targets;

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

    if (getenv("E9AFL_DEBUG") != nullptr)
        option_debug = true;
    if (getenv("E9AFL_NO_INSTRUMENT") != nullptr)
    {
        option_no_instrument = true;
        return nullptr;
    }

    // Send the AFL runtime (if not shared object):
    const ELF *rt = parseELF("afl-rt", afl_rt_ptr);
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
 * Optimize the targets.  Selects the best instruction in a BB to instrument.
 */
static void optimizeTargets(const ELF *elf, const Instr *Is, size_t size,
    std::set<intptr_t> &targets)
{
    std::set<intptr_t> new_targets;

    for (auto target: targets)
    {
        size_t i = findInstr(Is, size, target);
        if (i >= size)
            continue;
        const Instr *I = Is + i;

        uint8_t target_size = I->size;
        for (++i; i < size && target_size < /*sizeof(jmpq)=*/5; i++)
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
        new_targets.insert(target);
    }
    unsigned bb = 0;
    for (size_t i = 0; option_debug && i < size; i++)
    {
        InstrInfo I0, *I = &I0;
        getInstrInfo(elf, Is + i, I);
        if (targets.find(I->address) != targets.end())
            fprintf(stderr, "\nBB_%u:\n", bb++);
        if (new_targets.find(I->address) != new_targets.end())
            fprintf(stderr, "%lx: \33[33m%s\33[0m\n", I->address,
                I->string.instr);
        else
            fprintf(stderr, "%lx: %s\n", I->address, I->string.instr);
    }

    targets.swap(new_targets);
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
            CFGAnalysis(elf, Is, size, targets);
            optimizeTargets(elf, Is, size, targets);
            break;
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
    return (targets.find(info->address) != targets.end());
}

/*
 * Patching.
 */
extern void e9_plugin_patch_v1(FILE *out, const ELF *elf,
    const Instr *Is, size_t size, size_t idx, const InstrInfo *info,
    void *context)
{
    if (targets.find(info->address) == targets.end())
        return;
    if (option_no_instrument)
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

