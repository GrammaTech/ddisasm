//===- AArch64Decoder.h -----------------------------------------*- C++ -*-===//
//
//  Copyright (c) 2020, The Binrat Developers.
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
//===----------------------------------------------------------------------===//
#include "AArch64Decoder.h"

souffle::SouffleProgram *AArch64Decoder::decode(const gtirb::Module &module,
                                                const std::vector<std::string> &DisasmOptions)
{
    assert(module.getAddress() && "Module has non-addressable section data.");
    gtirb::Addr minAddr = *module.getAddress();
    assert(module.getSize() && "Module has non-calculable size.");
    gtirb::Addr maxAddr = *module.getAddress() + *module.getSize();

    for(const gtirb::Section &section : module.sections())
    {
        bool is_executable = section.isFlagSet(gtirb::SectionFlag::Executable);
        bool is_initialized = section.isFlagSet(gtirb::SectionFlag::Initialized);
        if(is_executable)
        {
            for(const auto &byteInterval : section.byte_intervals())
            {
                decodeSection(byteInterval);
                storeDataSection(byteInterval, minAddr, maxAddr);
            }
        }
        if(is_initialized)
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

void AArch64Decoder::decodeSection(const gtirb::ByteInterval &byteInterval)
{
    assert(byteInterval.getAddress() && "Failed to decode section without address.");
    assert(byteInterval.getSize() == byteInterval.getInitializedSize()
           && "Failed to decode section with partially initialized byte interval.");

    gtirb::Addr ea = byteInterval.getAddress().value();
    uint64_t size = byteInterval.getInitializedSize();
    auto buf = byteInterval.rawBytes<const unsigned char>();
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
            cs_free(insn, count);
        }
        ++ea;
        ++buf;
        --size;
    }
}
