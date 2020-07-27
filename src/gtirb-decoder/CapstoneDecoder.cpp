//===- CapstoneDecoder.cpp --------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
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
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#include "CapstoneDecoder.h"

#include <algorithm>
#include <string>

template <typename T>
std::optional<Instruction> CapstoneDecoder::disasm(T cs_detail::*Arch, const uint8_t* Bytes,
                                                   uint64_t Size, uint64_t Addr)
{
    cs_insn* Instruction;
    size_t Count = cs_disasm(CsHandle, Bytes, Size, Addr, 1, &Instruction);
    if(Count > 0)
    {
        return build(*Instruction, Arch);
    }
    cs_free(Instruction, Count);
    return std::nullopt;
}

template <typename T>
std::optional<Instruction> CapstoneDecoder::build(T cs_detail::*Arch, const cs_insn& CsInstruction)
{
    const auto& Details = CsInstruction.detail->*Arch;
    auto [Prefix, Name] = splitMnemonic(CsInstruction);
    std::vector<uint64_t> OpCodes;

    if(Name != "NOP")
    {
        int OpCount = Details.op_count;
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            const auto& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<Operand> Op = build(CsOp);
            if(!Op)
            {
                return std::nullopt;
            }

            // Add operand to the operands table.
            uint64_t OpIndex = std::visit(Operands, *Op);
            OpCodes.push_back(OpIndex);
        }
        // Put the destination operand at the end of the operand list.
        if(OpCount > 0)
        {
            std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
        }
    }

    uint64_t Addr(CsInstruction.address), Size(CsInstruction.size);
    uint8_t Imm(Details.encoding.imm_offset), Disp(Details.encoding.disp_offset);
    return Instruction{Addr, Size, Prefix, Name, OpCodes, Imm, Disp};
}

std::tuple<std::string, std::string> CapstoneDecoder::splitMnemonic(const cs_insn& CsInstruction)
{
    // FIXME:
    auto str_toupper = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<unsigned char>(std::toupper(c)); });
        return s;
    };

    std::string PrefixName = str_toupper(CsInstruction.mnemonic);
    std::string Prefix, Name;
    size_t Pos = PrefixName.find(' ');
    if(Pos != std::string::npos)
    {
        Prefix = PrefixName.substr(0, Pos);
        Name = PrefixName.substr(Pos + 1);
    }
    else
    {
        Prefix = "";
        Name = PrefixName;
    }
    return {Prefix, Name};
}
