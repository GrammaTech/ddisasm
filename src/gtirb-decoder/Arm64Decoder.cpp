//===- Arm64Decoder.cpp -----------------------------------------*- C++ -*-===//
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
#include "Arm64Decoder.h"

souffle::SouffleProgram *Arm64Decoder::decode(const gtirb::Module &module,
                                              const std::vector<std::string> &DisasmOptions)
{
    assert(module.getAddress() && "Module has non-addressable section data.");
    gtirb::Addr minAddr = *module.getAddress();
    assert(module.getSize() && "Module has non-calculable size.");
    gtirb::Addr maxAddr = *module.getAddress() + *module.getSize();

    for(const gtirb::Section &section : module.sections())
    {
        bool Exec = section.isFlagSet(gtirb::SectionFlag::Executable);
        bool Init = section.isFlagSet(gtirb::SectionFlag::Initialized);
        if(Exec)
        {
            for(const auto &byteInterval : section.byte_intervals())
            {
                decodeSection(byteInterval);
                storeDataSection(byteInterval, minAddr, maxAddr);
            }
        }
        else if(Init)
        {
            for(const auto &byteInterval : section.byte_intervals())
            {
                storeDataSection(byteInterval, minAddr, maxAddr);
            }
        }
    }
    if(auto *prog = souffle::ProgramFactory::newInstance("souffle_disasm_arm64"))
    {
        loadInputs(prog, module);
        GtirbToDatalog::addToRelation<std::vector<std::string>>(prog, "option", DisasmOptions);
        return prog;
    }
    return nullptr;
}

void Arm64Decoder::decodeSection(const gtirb::ByteInterval &byteInterval)
{
    assert(byteInterval.getAddress() && "Failed to decode section without address.");
    assert(byteInterval.getSize() == byteInterval.getInitializedSize()
           && "Failed to decode section with partially initialized byte interval.");

    gtirb::Addr ea = *byteInterval.getAddress();
    uint64_t size = byteInterval.getInitializedSize();
    const auto *buf = byteInterval.rawBytes<const uint8_t>();
    while(size > 0)
    {
        cs_insn *insn;
        size_t count =
            cs_disasm(CsHandle.getHandle(), buf, size, static_cast<uint64_t>(ea), 1, &insn);
        if(count == 0)
        {
            invalids.push_back(ea);
        }
        else
        {
            instructions.push_back(GtirbToDatalog::transformInstruction(CsHandle, op_dict, *insn));
        }
        cs_free(insn, count);
        ea += 4;
        buf += 4;
        size -= 4;
    }
}
