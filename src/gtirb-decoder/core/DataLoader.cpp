//===- DataLoader.cpp -------------------------------------------*- C++ -*-===//
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
#include "DataLoader.h"
#include "../../AuxDataSchema.h"
#include "../Endian.h"

void DataLoader::operator()(const gtirb::Module& Module, DatalogProgram& Program)
{
    DataFacts Facts;
    load(Module, Facts);

    Program.insert("data_byte", std::move(Facts.Bytes));
    Program.insert("address_in_data", std::move(Facts.Addresses));
    Program.insert("ascii_string", std::move(Facts.Ascii));
}

void DataLoader::load(const gtirb::Module& Module, DataFacts& Facts)
{
    std::optional<gtirb::Addr> Min, Max;
    for(const auto& Section : Module.sections())
    {
        std::optional<gtirb::Addr> Addr = Section.getAddress();
        std::optional<uint64_t> Size = Section.getSize();

        if(!Min || (Addr && *Addr < *Min))
        {
            Min = Addr;
        }
        if(!Max || (Addr && Size && (*Addr + *Size) > *Max))
        {
            Max = *Addr + *Size;
        }
    }
    assert(Min && Max && "Module has empty memory image.");
    Facts.Min = *Min;
    Facts.Max = *Max;

    for(const auto& Section : Module.sections())
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);
        bool Loaded = Section.isFlagSet(gtirb::SectionFlag::Loaded);

        if(Loaded && (Executable || Initialized))
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                load(ByteInterval, Facts);
            }
        }
    }
}

void DataLoader::load(const gtirb::ByteInterval& ByteInterval, DataFacts& Facts)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    gtirb::Addr Addr = *ByteInterval.getAddress();
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const int8_t>();

    size_t Ascii = 0;

    while(Size > 0)
    {
        // Single byte.
        uint8_t Byte = *Data;
        Facts.Bytes.push_back({Addr, Byte});

        // Possible address.
        if(Size >= static_cast<uint64_t>(PointerSize))
        {
            gtirb::Addr Value;

            switch(PointerSize)
            {
                case Pointer::DWORD:
                {
                    uint32_t Bytes = *((int32_t*)Data);
                    Bytes = (Endianness == Endian::BIG) ? be32toh(Bytes) : le32toh(Bytes);
                    Value = gtirb::Addr(Bytes);
                    break;
                }
                case Pointer::QWORD:
                {
                    uint64_t Bytes = *((int64_t*)Data);
                    Bytes = (Endianness == Endian::BIG) ? be64toh(Bytes) : le64toh(Bytes);
                    Value = gtirb::Addr(Bytes);
                    break;
                }
            }

            if((Value >= Facts.Min) && (Value <= Facts.Max))
            {
                Facts.Addresses.push_back({Addr, Value});
            }
        }

        // Possible ASCII character.
        if(std::isprint(Byte) || std::isspace(Byte))
        {
            Ascii++;
        }
        else if(Byte == 0 && Ascii > 0)
        {
            Facts.Ascii.push_back({Addr - Ascii, Ascii + 1});
            Ascii = 0;
        }
        else
        {
            Ascii = 0;
        }

        ++Addr;
        ++Data;
        --Size;
    }
}
