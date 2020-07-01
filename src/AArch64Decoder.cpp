#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

#include "AArch64Decoder.h"
#include "AuxDataSchema.h"
#include "ExceptionDecoder.h"

/**
 * AArch64 Decoder
 * Currently uses the x86 variant just to ensure that we have a sound
 * structure to the project
 */
souffle::SouffleProgram *AArch64Decoder::decode(gtirb::Module &module,
                                                const std::vector<std::string> &DisasmOptions)
{
    assert(module.getSize() && "Module has non-calculable size.");
    gtirb::Addr minAddr = *module.getAddress();

    assert(module.getAddress() && "Module has non-addressable section data.");
    gtirb::Addr maxAddr = *module.getAddress() + *module.getSize();

    for(auto &section : module.sections())
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
    if(auto prog = souffle::ProgramFactory::newInstance("souffle_disasm_aarch64"))
    {
        loadInputs(prog, module);
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
            cs_disasm(CsHandle.RawHandle, buf, size, static_cast<uint64_t>(ea), 1, &insn);
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
