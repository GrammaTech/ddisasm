#include "Functors.h"

#include <sys/stat.h>

#include <fstream>
#include <iostream>

const gtirb::Module* Module = nullptr;
bool IsBigEndian = false;

static const gtirb::ByteInterval* getByteInterval(uint64_t EA, size_t Size)
{
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
    const gtirb::ByteInterval* ByteInterval = getByteInterval(EA, Size);
    return ByteInterval != nullptr ? 1 : 0;
}

static void readData(uint64_t EA, uint8_t* Buffer, size_t Count)
{
    const gtirb::ByteInterval* ByteInterval = getByteInterval(EA, Count);
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
    const char* DebugDir = std::getenv("DDISASM_DEBUG_DIR");
    if(!DebugDir)
    {
        std::cerr << "ERROR: DDISASM_DEBUG_DIR not set\n";
        return;
    }
    std::string GtirbPath(DebugDir);
    GtirbPath.append("/binary.gtirb");

    Context = std::make_unique<gtirb::Context>();

    std::ifstream Stream(GtirbPath, std::ios::in | std::ios::binary);
    gtirb::ErrorOr<gtirb::IR*> Result = gtirb::IR::load(*Context, Stream);
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

    auto Modules = IR->modules();
    const gtirb::Module* M = nullptr;
    for(auto It = Modules.begin(); It != Modules.end(); It++)
    {
        if(It->getName().compare(ModuleName) == 0)
        {
            M = &(*It);
            break;
        }
    }
    if(M == nullptr)
    {
        std::cerr << "ERROR: No module with name: " << ModuleName << "\n";
        return;
    }

    initFunctorGtirbModule(M);
}
#endif /* __EMBEDDED_SOUFFLE__ */
