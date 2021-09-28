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

#ifdef _WIN32
#include <windows.h>
#endif // _WIN32

#if defined(_WIN32) || defined(__APPLE__)
#if defined(_MSC_VER)

#define be32toh(x) _byteswap_ulong(x)
#define le32toh(x) (x)

#define be64toh(x) _byteswap_uint64(x)
#define le64toh(x) (x)

#elif defined(__GNUC__) || defined(__clang__)

#define be32toh(x) __builtin_bswap32(x)
#define le32toh(x) (x)

#define be64toh(x) __builtin_bswap64(x)
#define le64toh(x) (x)

#endif // _MSC_VER
#endif // defined(_WIN32) || defined(__APPLE__)

#include "../../AuxDataSchema.h"
#include "../UTF16.h"
#include "../UTF8.h"

void DataLoader::operator()(const gtirb::Module& Module, DatalogProgram& Program)
{
    DataFacts Facts;
    load(Module, Facts);

    Program.insert("data_byte", std::move(Facts.Bytes));
    Program.insert("address_in_data", std::move(Facts.Addresses));
    Program.insert("ascii_string", std::move(Facts.Ascii));
    Program.insert("utf8_string", std::move(Facts.Utf8));
    Program.insert("utf16_le_string", std::move(Facts.Utf16));
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
    Unicode Utf8 = {gtirb::Addr(0), 0, UTF8_ACCEPT, 0};
    Unicode Utf16 = {gtirb::Addr(0), 0, UTF16_ACCEPT, 0};

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
                    Bytes = (Endianness == Endianness::BIG) ? be32toh(Bytes) : le32toh(Bytes);
                    Value = gtirb::Addr(Bytes);
                    break;
                }
                case Pointer::QWORD:
                {
                    uint64_t Bytes = *((int64_t*)Data);
                    Bytes = (Endianness == Endianness::BIG) ? be64toh(Bytes) : le64toh(Bytes);
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
        if(std::isprint(Byte))
        {
            Ascii++;
        }
        else if(Byte == 0 && Ascii > StringLimit)
        {
            Facts.Ascii.push_back({Addr - Ascii, Ascii});
            Ascii = 0;
        }
        else
        {
            Ascii = 0;
        }

        // Possible UTF-8 byte.
        if(Byte == 0 && Utf8.State == UTF8_ACCEPT && Utf8.Length > StringLimit)
        {
            uint64_t Size = static_cast<uint64_t>(Addr - Utf8.Addr);
            Facts.Utf8.push_back({Utf8.Addr, Size, Utf8.Length});
            Utf8 = {gtirb::Addr(0), 0, UTF8_ACCEPT, 0};
        }
        else if(Byte != 0)
        {
            switch(utf8::decode(&Utf8.State, &Utf8.Codepoint, Byte))
            {
                case UTF8_ACCEPT:
                    // Complete character.
                    if(Utf8.Addr == gtirb::Addr(0))
                    {
                        Utf8.Addr = Addr;
                    }
                    Utf8.Length++;
                    break;
                case UTF8_REJECT:
                    // Invalid sequence.
                    Utf8 = {gtirb::Addr(0), 0, UTF8_ACCEPT, 0};
                    break;
                default:
                    // Incomplete character.
                    if(Utf8.Addr == gtirb::Addr(0))
                    {
                        Utf8.Addr = Addr;
                    }
                    break;
            }
        }
        else
        {
            // String was invalid or too small.
            Utf8 = {gtirb::Addr(0), 0, UTF8_ACCEPT, 0};
        }

        // Possible UTF-16 LE byte.
        bool Null = Utf16.State == UTF16_ACCEPT && Utf16.Codepoint == 0 && Utf16.Length > 0;
        if(Null && Utf16.Length > StringLimit)
        {
            uint64_t Size = static_cast<uint64_t>(Addr - Utf16.Addr);
            Facts.Utf16.push_back({Utf16.Addr, Size, Utf16.Length});
            Utf16 = {gtirb::Addr(0), 0, UTF16_ACCEPT, 0};
        }
        else if(!Null)
        {
            switch(utf16::le::decode(&Utf16.State, &Utf16.Codepoint, Byte))
            {
                case UTF16_ACCEPT:
                    // Complete character.
                    if(Utf16.Addr == gtirb::Addr(0))
                    {
                        Utf16.Addr = Addr;
                    }
                    Utf16.Length++;
                    break;
                case UTF16_REJECT:
                    // Invalid sequence.
                    Utf16 = {gtirb::Addr(0), 0, UTF16_ACCEPT, 0};
                    break;
                default:
                    // Incomplete character.
                    if(Utf16.Addr == gtirb::Addr(0))
                    {
                        Utf16.Addr = Addr;
                    }
                    break;
            }
        }
        else
        {
            // String was invalid or too small.
            Utf16 = {gtirb::Addr(0), 0, UTF16_ACCEPT, 0};
        }

        ++Addr;
        ++Data;
        --Size;
    }
}
