//===- IsaSupport.h ---------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2026 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public
//  License for more details.
//
//===----------------------------------------------------------------------===//
#ifndef SRC_ISA_SUPPORT_H_
#define SRC_ISA_SUPPORT_H_

#include <gtirb/gtirb.hpp>

/**
 * isExperimentalIsa
 * Determine whether the given ISA is one of the newly supported, experimental
 * ISAs. Behavior added for these ISAs (big-endian eh_frame parsing, TLS base
 * aux data, PLT return edges) is restricted to them so that the established
 * ISAs (x86, x64, ARM, ARM64, MIPS32) keep their existing behavior.
 * Input:  ISA - the module's instruction set architecture
 * Output: true if the ISA is PPC32, PPC64, MIPS64, RISCV32 or RISCV64
 */
inline bool isExperimentalIsa(gtirb::ISA ISA)
{
    switch(ISA)
    {
        case gtirb::ISA::PPC32:
        case gtirb::ISA::PPC64:
        case gtirb::ISA::MIPS64:
        case gtirb::ISA::RISCV32:
        case gtirb::ISA::RISCV64:
            return true;
        default:
            return false;
    }
}

#endif // SRC_ISA_SUPPORT_H_
