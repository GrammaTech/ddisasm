//===- DatalogLoader.h ------------------------------------------*- C++ -*-===//
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

#include "DatalogLoader.h"

void DatalogLoader::load(const gtirb::Context& Context, const gtirb::Module& Module)
{
    // Load all GTIRB sections.
    for(const auto& Section : Module.sections())
    {
        Sections.load(Section);
    }

    // Build the Souffle context.
    // ...
}

void SectionDecoder::load(const gtirb::Section& Section)
{
    bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
    bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);

    if(Executable)
    {
        for(const auto& ByteInterval : Section.byte_intervals())
        {
            Code.load(ByteInterval);
            Data.load(ByteInterval);
        }
    }
    else if(Initialized)
    {
        for(const auto& ByteInterval : Section.byte_intervals())
        {
            Data.load(ByteInterval);
        }
    }
}

void InstructionDecoder::load(const gtirb::ByteInterval& ByteInterval)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    gtirb::Addr Addr = *ByteInterval.getAddress();
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    while(Size > 0)
    {
        if(std::optional<Instruction> Instruction = decode(Data, Size))
        {
            Instructions.push_back(*Instruction);
        }
        else
        {
            InvalidInstructions.push_back(Addr);
        }
        ++Addr;
        ++Data;
        --Size;
    }
}

void DataDecoder::load(const gtirb::ByteInterval& ByteInterval)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    const gtirb::Section* Section = ByteInterval.getSection();
    assert(Section && "ByteInterval does not belong to a Section.");

    const gtirb::Module* Module = Section->getModule();
    assert(Module && "Section does not belong to a Module.");

    assert(Module->getSize() && "Module has non-calculable size.");
    gtirb::Addr Start = *Module->getAddress();

    assert(Module->getAddress() && "Module has non-addressable section data.");
    gtirb::Addr End = *Module->getAddress() + *Module->getSize();

    auto PossibleAddress = [Start, End](gtirb::Addr Value) {
        return ((Value >= Start) && (Value <= Value));
    };

    gtirb::Addr Addr = *ByteInterval.getAddress();
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    // FIXME: Window size should be sensitive to the architecture.
    while(Size >= 8)
    {
        // Store single byte.
        uint8_t Byte = *Data;
        Bytes.push_back({Addr, Byte});

        // Store address.
        if(Size >= 8)
        {
            gtirb::Addr Value(*((int64_t*)Data));
            if(PossibleAddress(Value))
            {
                Addresses.push_back({Addr, Value});
            }
        }

        ++Addr;
        ++Data;
        --Size;
    }
}
