//===- InstructionLoader.cpp ------------------------------------*- C++ -*-===//
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
//  GNU Affero General Public License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "InstructionLoader.h"

std::string uppercase(std::string S)
{
    std::transform(S.begin(), S.end(), S.begin(),
                   [](unsigned char C) { return static_cast<unsigned char>(std::toupper(C)); });
    return S;
};

/**
The given OperandFacts should have only one operand.
Insert it to this object and return the corresponding OpIndex.
*/
std::optional<uint64_t> OperandFacts::insert(const OperandFacts& OpndFacts)
{
    std::optional<uint64_t> OpIndex;

    const auto& imm = OpndFacts.imm();
    const auto& reg = OpndFacts.reg();
    const auto& reg_bitfields = OpndFacts.reg_bitfields_raw();
    const auto& fp_imm = OpndFacts.fp_imm();
    const auto& indirect = OpndFacts.indirect();
    const auto& special = OpndFacts.special();
    if(imm.size() + reg.size() + reg_bitfields.size() + fp_imm.size() + indirect.size()
           + special.size()
       != 1)
    {
        return OpIndex;
    }

    if(imm.size() == 1)
    {
        OpIndex = this->add(imm.begin()->first);
    }
    else if(reg.size() == 1)
    {
        OpIndex = this->add(reg.begin()->first);
    }
    else if(reg_bitfields.size() == 1)
    {
        OpIndex = this->add(reg_bitfields.begin()->first);
    }
    else if(fp_imm.size() == 1)
    {
        OpIndex = this->add(fp_imm.begin()->first);
    }
    else if(indirect.size() == 1)
    {
        OpIndex = this->add(indirect.begin()->first);
    }
    else if(special.size() == 1)
    {
        OpIndex = this->add(special.begin()->first);
    }
    return OpIndex;
}

const std::vector<relations::RegBitFieldOp> OperandFacts::reg_bitfields() const
{
    std::vector<relations::RegBitFieldOp> RegBitFieldsForSouffle;
    for(auto It = RegBitFields.begin(); It != RegBitFields.end(); ++It)
    {
        auto Regs = It->first;
        auto Index = It->second;
        for(auto It2 = Regs.begin(); It2 != Regs.end(); ++It2)
        {
            auto K = relations::RegBitFieldOp{Index, *It2};
            RegBitFieldsForSouffle.push_back(K);
        }
    }
    return RegBitFieldsForSouffle;
}

/**
Insert BinaryFacts into the Datalog program.
*/
void InstructionLoader::insert(const BinaryFacts& Facts, DatalogProgram& Program)
{
    auto& [Instructions, Operands] = Facts;
    Program.insert("instruction", Instructions.instructions());
    Program.insert("instruction_writeback", Instructions.writeback());
    Program.insert("invalid_op_code", Instructions.invalid());
    Program.insert("op_shifted", Instructions.shiftedOps());
    Program.insert("op_shifted_w_reg", Instructions.shiftedWithRegOps());
    Program.insert("register_access", Instructions.registerAccesses());
    Program.insert("op_immediate", Operands.imm());
    Program.insert("op_regdirect", Operands.reg());
    Program.insert("op_fp_immediate", Operands.fp_imm());
    Program.insert("op_indirect", Operands.indirect());
    Program.insert("op_special", Operands.special());
    Program.insert("op_register_bitfield", Operands.reg_bitfields());
}

/**
Load register access facts
*/
void InstructionLoader::loadRegisterAccesses(BinaryFacts& Facts, uint64_t Addr,
                                             const cs_insn& CsInstruction)
{
    cs_regs RegsRead, RegsWrite;
    uint8_t RegsReadCount, RegsWriteCount;
    if(cs_regs_access(*CsHandle, &CsInstruction, RegsRead, &RegsReadCount, RegsWrite,
                      &RegsWriteCount)
       != CS_ERR_OK)
    {
        assert(!"cs_regs_access failed");
    }

    gtirb::Addr GtirbAddr = gtirb::Addr(Addr);

    for(uint8_t i = 0; i < RegsReadCount; i++)
    {
        Facts.Instructions.registerAccess(relations::RegisterAccess{
            GtirbAddr, "R", uppercase(cs_reg_name(*CsHandle, RegsRead[i]))});
    }
    for(uint8_t i = 0; i < RegsWriteCount; i++)
    {
        Facts.Instructions.registerAccess(relations::RegisterAccess{
            GtirbAddr, "W", uppercase(cs_reg_name(*CsHandle, RegsWrite[i]))});
    }
}
