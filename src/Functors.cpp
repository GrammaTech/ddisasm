#include "Functors.h"

#include <fstream>
#include <iostream>

const gtirb::Module* Module = nullptr;
bool IsBigEndian = false;

static const gtirb::ByteInterval* get_byte_interval(uint64_t EA, size_t Size)
{
    // TODO: maybe this is too slow for the functor
    for(const auto& Section : Module->sections())
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);
        bool Loaded = Section.isFlagSet(gtirb::SectionFlag::Loaded);
        if(Loaded && (Executable || Initialized))
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
                uint64_t IntervalSize = ByteInterval.getInitializedSize();
                if(EA < Addr || EA + Size > Addr + IntervalSize)
                {
                    continue;
                }
                return &ByteInterval;
            }
        }
    }
    return nullptr;
}

uint64_t functor_data_exists(uint64_t EA, size_t Size)
{
    const gtirb::ByteInterval* ByteInterval = get_byte_interval(EA, Size);
    return ByteInterval != nullptr ? 1 : 0;
}

static void readData(uint64_t EA, uint8_t* Buffer, size_t Count)
{
    const gtirb::ByteInterval* ByteInterval = get_byte_interval(EA, Count);
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

uint64_t functor_data_u8(uint64_t EA)
{
    uint8_t Value;
    readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return Value;
}

int64_t functor_data_s16(uint64_t EA)
{
    uint16_t Value;
    readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int16_t>(IsBigEndian ? be16toh(Value) : le16toh(Value));
}

int64_t functor_data_s32(uint64_t EA)
{
    uint32_t Value;
    readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int32_t>(IsBigEndian ? be32toh(Value) : le32toh(Value));
}

int64_t functor_data_s64(uint64_t EA)
{
    uint64_t Value;
    readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int64_t>(IsBigEndian ? be64toh(Value) : le64toh(Value));
}

void initFunctorGtirbModule(const gtirb::Module* M)
{
    // TODO: build a sorted Range => ByteInterval map. This will allow a binary
    // search to find the right range quickly.
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

std::unique_ptr<gtirb::Context> Context;

/*
Load the GTIRB file from the debug directory if running in the interpreter
*/
void __attribute__((constructor)) loadGtirb(void)
{
    // TODO: locate fact-dir in the command line args
    const std::string GtirbPath("debug/binary.gtirb");

    Context = std::make_unique<gtirb::Context>();

    std::ifstream Stream(GtirbPath, std::ios::in | std::ios::binary);
    gtirb::ErrorOr<gtirb::IR*> Result = gtirb::IR::load(*Context, Stream);
    if(!Result)
    {
        std::cerr << "ERROR: Failed to load GTIRB: " << GtirbPath << "\n";
        return;
    }

    // TODO: support multi-module GTIRB files (static archives)
    gtirb::IR* IR = *Result;
    initFunctorGtirbModule(&(*IR->modules().begin()));
}
#endif /* __EMBEDDED_SOUFFLE__ */
