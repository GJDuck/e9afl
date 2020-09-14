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

#include <sstream>
#include <string>
#include <set>

#include "e9plugin.h"

using namespace e9frontend;

#define AREA_BASE   0x200000
#define AREA_SIZE   ((size_t)1 << 16)

bool option_no_instrument = false;

/*
 * To compile:
 *      $ g++ -std=c++11 -fPIC -shared -o e9afl.so -O2 e9afl.cpp \
 *          -I . -I capstone/include/
 */

/*
 * Jump/call target information.
 */
static std::set<intptr_t> targets;
bool alive = false;

/*
 * Initialization.
 */
extern void *e9_plugin_init_v1(FILE *out, const e9frontend::ELF *elf)
{
    const int32_t stack_adjust = 0x4000;
    const int32_t afl_rt_ptr   = 0x1d0000;
    const int32_t afl_area_ptr = AREA_BASE;

    // Reserve memory used by the afl_area_ptr:
    sendReserveMessage(out, afl_area_ptr, AREA_SIZE, /*absolute=*/true);

    if (getenv("E9AFL_NO_INSTRUMENT") != nullptr)
    {
        option_no_instrument = true;
        return nullptr;
    }

    // Send the AFL runtime:
    const ELF *rt = parseELF("afl-rt", afl_rt_ptr);
    sendELFFileMessage(out, rt, /*absolute=*/true);

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
 * Instruction.  Look for targets.
 */
extern void e9_plugin_instr_v1(FILE *out, const e9frontend::ELF *elf,
    csh handle, off_t offset, const cs_insn *I, void *context)
{
    if (!alive && I->id != X86_INS_NOP)
    {
        // First non-NOP instruction after a unconditional branch/return is
        // considered to be a target:
        targets.insert(I->address);
        alive = true;
    }

    /*
     * We aim to instrument:
     *
     * ^main:      - function entry point (always instrumented)
     * ^.L0:       - branch label
     * ^.LBB0_0:   - branch label
     * ^\tjnz foo  - conditional branches
     */
    const cs_detail *detail = I->detail;
    switch (I->id)
    {
        case X86_INS_RET:
            alive = false;
            return;
        case X86_INS_JMP:
            alive = false;
            break;
        case X86_INS_CALL:
            break;
        case X86_INS_JO: case X86_INS_JNO: case X86_INS_JB: case X86_INS_JAE:
        case X86_INS_JE: case X86_INS_JNE: case X86_INS_JBE: case X86_INS_JA:
        case X86_INS_JS: case X86_INS_JNS: case X86_INS_JP: case X86_INS_JNP:
        case X86_INS_JL: case X86_INS_JGE: case X86_INS_JLE: case X86_INS_JG:
        {
            // For conditional jumps, the next instruction is also considered
            // a target (for the fall-through case):
            int64_t target = (I->address + I->size);
            targets.insert(target);
            break;
        }
        default:
            // Not a control-flow-transfer:
            return;
    }
    const cs_x86_op *op = &detail->x86.operands[0];
    int64_t target = -1;
    switch (op->type)
    {
        case X86_OP_IMM:
            target = op->imm;
            break;
        default:
            // Indirect
            return;
    }
    targets.insert(target);
}

/*
 * Matching.  Return `true' iff we should instrument this instruction.
 */
extern intptr_t e9_plugin_match_v1(FILE *out, const e9frontend::ELF *elf,
    csh handle, off_t offset, const cs_insn *I, void *context)
{
    bool target = (targets.find(I->address) != targets.end());
    if (!target)
        return false;

    if (I->size > 1)
        return true;

    // This is a single-byte instruction, which means that E9Patch will have
    // poor coverage.  Attempt to defer the instrumentation to the next
    // instruction which will hopefully be multi-byte.

    if (I->id == X86_INS_RET) 
        return true;                // Cannot defer: single-byte CFT.
    if (targets.find(I->address + I->size) != targets.end())
        return true;                // Cannot defer: next instr is target.

    targets.erase(I->address);
    targets.insert(I->address + I->size);

    return false;
}

/*
 * Patching.
 */
extern void e9_plugin_patch_v1(FILE *out, const e9frontend::ELF *elf,
    csh handle, off_t offset, const cs_insn *I, void *context)
{
    if (targets.find(I->address) == targets.end())
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

    sendPatchMessage(out, "afl", offset, metadata);
}

