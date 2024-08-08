//===- Functors.cpp ---------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2022 GrammaTech, Inc.
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
#include "Functors.h"

#include <cassert>
#include <fstream>
#include <iostream>

#include "Endian.h"

namespace
{
    template <int Bits>
    static inline int32_t sign_extend32(uint32_t Val)
    {
        assert(Bits > 0 && Bits <= 32);
        if(Bits == 32)
        {
            return static_cast<int32_t>(Val);
        }
        uint32_t Mask = (~static_cast<uint32_t>(0)) >> (32 - Bits);
        Val &= Mask;
        uint32_t TopBit = 1U << (Bits - 1);
        int32_t Signed = static_cast<int32_t>(Val);
        if((Val & TopBit) != 0)
        {
            Signed -= static_cast<int32_t>(TopBit * 2);
        }
        return Signed;
    }

} // namespace

FunctorContextManager FunctorContext;

const gtirb::ByteInterval* FunctorContextManager::getByteInterval(uint64_t EA, size_t Size)
{
    for(const auto& Section : Module->findSectionsOn(gtirb::Addr(EA)))
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);
        bool Loaded = Section.isFlagSet(gtirb::SectionFlag::Loaded);
        if(Loaded && (Executable || Initialized))
        {
            for(const auto& ByteInterval : Section.findByteIntervalsOn(gtirb::Addr(EA)))
            {
                uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
                uint64_t IntervalSize = ByteInterval.getInitializedSize();
                if(EA + Size > Addr + IntervalSize)
                {
                    continue;
                }
                return &ByteInterval;
            }
        }
    }
    return nullptr;
}

uint64_t functor_data_valid(uint64_t EA, size_t Size)
{
    if(!(Size == 1 || Size == 2 || Size == 4 || Size == 8))
    {
        return 0;
    }
    const gtirb::ByteInterval* ByteInterval = FunctorContext.getByteInterval(EA, Size);
    return ByteInterval != nullptr ? 1 : 0;
}

void FunctorContextManager::readData(uint64_t EA, uint8_t* Buffer, size_t Count)
{
    const gtirb::ByteInterval* ByteInterval = FunctorContext.getByteInterval(EA, Count);
    if(ByteInterval == nullptr)
    {
        memset(Buffer, 0, Count);
        return;
    }
    uint64_t Addr = static_cast<uint64_t>(*ByteInterval->getAddress());
    auto Data = ByteInterval->rawBytes<const uint8_t>();

    // memcpy: safely handles unaligned requests.
    memcpy(Buffer, Data + EA - Addr, Count);
}

uint64_t functor_data_unsigned(uint64_t EA, size_t Size)
{
    switch(Size)
    {
        case 1:
            return functor_data_u8(EA);
        case 2:
            return functor_data_u16(EA);
        case 4:
            return functor_data_u32(EA);
        case 8:
            return functor_data_u64(EA);
        default:
            assert(!"Invalid size");
    }
    return 0;
}

uint64_t functor_data_u8(uint64_t EA)
{
    uint8_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return Value;
}

uint64_t functor_data_u16(uint64_t EA)
{
    uint16_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return FunctorContext.IsBigEndian ? be16toh(Value) : le16toh(Value);
}

uint64_t functor_data_u32(uint64_t EA)
{
    uint32_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return FunctorContext.IsBigEndian ? be32toh(Value) : le32toh(Value);
}

uint64_t functor_data_u64(uint64_t EA)
{
    uint64_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return FunctorContext.IsBigEndian ? be64toh(Value) : le64toh(Value);
}

int64_t functor_data_signed(uint64_t EA, size_t Size)
{
    switch(Size)
    {
        case 1:
            return functor_data_s8(EA);
        case 2:
            return functor_data_s16(EA);
        case 4:
            return functor_data_s32(EA);
        case 8:
            return functor_data_s64(EA);
        default:
            assert(!"Invalid size");
    }
    return 0;
}

int64_t functor_data_s8(uint64_t EA)
{
    uint8_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int8_t>(Value);
}

int64_t functor_data_s16(uint64_t EA)
{
    uint16_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int16_t>(FunctorContext.IsBigEndian ? be16toh(Value) : le16toh(Value));
}

int64_t functor_data_s32(uint64_t EA)
{
    uint32_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int32_t>(FunctorContext.IsBigEndian ? be32toh(Value) : le32toh(Value));
}

int64_t functor_data_s64(uint64_t EA)
{
    uint64_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int64_t>(FunctorContext.IsBigEndian ? be64toh(Value) : le64toh(Value));
}

uint64_t functor_aligned(uint64_t EA, size_t Size)
{
    return EA + ((Size - (EA % Size)) % Size);
}

uint64_t functor_choose_max(int64_t Val1, int64_t Val2, uint64_t Id1, uint64_t Id2)
{
    if(Val1 <= Val2)
    {
        return Id2;
    }
    else
    {
        return Id1;
    }
}

// Decode the branch offset of a 32-bit THUMB branch instruction. Used to find
// REL relocation addends. Backward compatible with THUMB-1 encoding.
int64_t functor_thumb32_branch_offset(uint32_t Instruction)
{
    uint16_t Hi = (uint16_t)(Instruction & 0xFFFFU);
    uint16_t Lo = (uint16_t)((Instruction >> 16) & 0xFFFFU);

    uint32_t S = (Hi & (1U << 10)) >> 10;
    uint32_t Upper = Hi & 0x3ffU;
    uint32_t Lower = Lo & 0x7ffU;
    uint32_t J1 = (Lo & (1U << 13)) >> 13;
    uint32_t J2 = (Lo & (1U << 11)) >> 11;
    uint32_t I1 = J1 ^ S ? 0 : 1;
    uint32_t I2 = J2 ^ S ? 0 : 1;

    return sign_extend32<25>((S << 24) | (I1 << 23) | (I2 << 22) | (Upper << 12) | (Lower << 1));
}

souffle::RamDomain to_string_hex(souffle::SymbolTable* symbolTable,
                                 [[maybe_unused]] souffle::RecordTable* recordTable,
                                 souffle::RamDomain Value)
{
    std::stringstream S;
    S << std::hex << Value;
    return symbolTable->encode(S.str());
}

void FunctorContextManager::useModule(const gtirb::Module* M)
{
    Module = M;

    // Check module's byte order
    switch(Module->getByteOrder())
    {
        case gtirb::ByteOrder::Big:
            IsBigEndian = true;
            break;
        case gtirb::ByteOrder::Little:
            IsBigEndian = false;
            break;
        case gtirb::ByteOrder::Undefined:
        default:
            std::cerr << "WARNING: GTIRB has undefined endianness (assuming little)\n";
            IsBigEndian = false;
    }
}

#ifndef __EMBEDDED_SOUFFLE__
/*
Load the GTIRB file from the debug directory

Used only for the interpreter.
*/
void FunctorContextManager::loadGtirb(void)
{
    const char* DebugDir = std::getenv("DDISASM_DEBUG_DIR");
    if(!DebugDir)
    {
        std::cerr << "ERROR: DDISASM_DEBUG_DIR not set\n";
        return;
    }
    std::string GtirbPath(DebugDir);
    GtirbPath.append("/binary.gtirb");

    GtirbContext = std::make_unique<gtirb::Context>();

    std::ifstream Stream(GtirbPath, std::ios::in | std::ios::binary);
    gtirb::ErrorOr<gtirb::IR*> Result = gtirb::IR::load(*GtirbContext, Stream);
    if(!Result)
    {
        std::cerr << "ERROR: Failed to load GTIRB: " << GtirbPath << "\n";
        return;
    }

    gtirb::IR* IR = *Result;

    // Locate the correct module
    const char* ModuleName = std::getenv("DDISASM_GTIRB_MODULE_NAME");
    if(!ModuleName)
    {
        std::cerr << "ERROR: DDISASM_GTIRB_MODULE_NAME not set\n";
        return;
    }

    auto Modules = IR->findModules(ModuleName);
    if(Modules.empty())
    {
        std::cerr << "ERROR: No module with name: " << ModuleName << "\n";
        return;
    }

    FunctorContext.useModule(&(*Modules.begin()));
}
#endif /* __EMBEDDED_SOUFFLE__ */
