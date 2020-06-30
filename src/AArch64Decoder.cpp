#include <souffle/CompiledSouffle.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

#include "AArch64Decoder.h"
#include "AuxDataSchema.h"
#include "BinaryReader.h"
#include "ExceptionDecoder.h"
#include "GtirbZeroBuilder.h"

AArch64Decoder::AArch64Decoder()
{
    cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &this->csHandle); // == CS_ERR_OK
    cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

AArch64Decoder::~AArch64Decoder()
{
    cs_close(&this->csHandle);
}

/**
 * AArch64 Decoder
 * Currently uses the x86 variant just to ensure that we have a sound
 * structure to the project
 */
souffle::SouffleProgram *AArch64Decoder::decode(gtirb::Module &module)
{
    assert(module.getSize() && "Module has non-calculable size.");
    gtirb::Addr minAddr = *module.getAddress();

    assert(module.getAddress() && "Module has non-addressable section data.");
    gtirb::Addr maxAddr = *module.getAddress() + *module.getSize();

    auto *extraInfoTable = module.getAuxData<gtirb::schema::ElfSectionProperties>();
    if(!extraInfoTable)
        throw std::logic_error("missing elfSectionProperties AuxData table");
    for(auto &section : module.sections())
    {
        auto found = extraInfoTable->find(section.getUUID());
        if(found == extraInfoTable->end())
            throw std::logic_error("Section " + section.getName()
                                   + " missing from elfSectionProperties AuxData table");
        SectionProperties &extraInfo = found->second;
        if(isExeSection(extraInfo))
        {
            for(const auto byteInterval : section.byte_intervals())
            {
                decodeSection(byteInterval);
                storeDataSection(byteInterval, minAddr, maxAddr);
            }
        }
        if(isNonZeroDataSection(extraInfo))
        {
            for(const auto byteInterval : section.byte_intervals())
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
        size_t count = cs_disasm(csHandle, buf, size, static_cast<uint64_t>(ea), 1, &insn);
        if(count == 0)
        {
            invalids.push_back(ea);
        }
        else
        {
            instructions.push_back(
                GtirbToDatalog::transformInstruction(CS_ARCH_ARM64, csHandle, op_dict, *insn));
            cs_free(insn, count);
        }
        ++ea;
        ++buf;
        --size;
    }
}
