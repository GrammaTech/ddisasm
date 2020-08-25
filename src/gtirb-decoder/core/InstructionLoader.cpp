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

void InstructionLoader::operator()(const gtirb::Module& Module, DatalogProgram& Program)
{
    load(Module);

    Program.insert("instruction_complete", Instructions);
    Program.insert("invalid_op_code", InvalidInstructions);
    Program.insert("op_immediate", Operands.ImmTable);
    Program.insert("op_regdirect", Operands.RegTable);
    Program.insert("op_indirect", Operands.IndirectTable);
}

void InstructionLoader::load(const gtirb::Module& Module)
{
    for(const auto& Section : Module.sections())
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        if(Executable)
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                load(ByteInterval);
            }
        }
    }
}

void InstructionLoader::load(const gtirb::ByteInterval& ByteInterval)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    while(Size > 0)
    {
        decode(Data, Size, Addr);
        Addr += InstructionSize;
        Data += InstructionSize;
        Size -= InstructionSize;
    }
}

std::string uppercase(std::string S)
{
    std::transform(S.begin(), S.end(), S.begin(),
                   [](unsigned char C) { return static_cast<unsigned char>(std::toupper(C)); });
    return S;
};
