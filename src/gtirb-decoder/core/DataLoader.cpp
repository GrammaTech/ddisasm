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

void DataLoader::operator()(const gtirb::Module& Module, DatalogProgram& Program)
{
    load(Module);

    Program.insert("data_byte", Bytes);
    Program.insert("address_in_data", Addresses);
}

void DataLoader::load(const gtirb::Module& Module)
{
    assert(Module.getSize() && "Module has non-calculable size.");
    Min = *Module.getAddress();

    assert(Module.getAddress() && "Module has non-addressable section data.");
    Max = *Module.getAddress() + *Module.getSize();

    for(const auto& Section : Module.sections())
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);

        if(Executable || Initialized)
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");
                load(ByteInterval);
            }
        }
    }
}

void DataLoader::load(const gtirb::ByteInterval& ByteInterval)
{
    gtirb::Addr Addr = *ByteInterval.getAddress();
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    while(Size > 0)
    {
        // Single byte.
        uint8_t Byte = *Data;
        Bytes.push_back({Addr, Byte});

        // Possible address.
        if(Size >= static_cast<uint64_t>(PointerSize))
        {
            gtirb::Addr Value;

            switch(PointerSize)
            {
                case Pointer::DWORD:
                    Value = gtirb::Addr(*((int32_t*)Data));
                    break;
                case Pointer::QWORD:
                    Value = gtirb::Addr(*((int64_t*)Data));
                    break;
            }

            if(address(Value))
            {
                Addresses.push_back({Addr, Value});
            }
        }

        ++Addr;
        ++Data;
        --Size;
    }
}
