#include <souffle/CompiledSouffle.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include "BinaryReader.h"
#include "ExceptionDecoder.h"
#include "GtirbZeroBuilder.h"
#include "AArch64Decoder.h"


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
    auto minMax = module.getImageByteMap().getAddrMinMax();
    auto *extraInfoTable =
        module.getAuxData<std::map<gtirb::UUID, SectionProperties>>("elfSectionProperties");
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
            gtirb::ImageByteMap::const_range bytes =
                gtirb::getBytes(module.getImageByteMap(), section);
            decodeSection(bytes, bytes.size(), section.getAddress());
            storeDataSection(bytes, bytes.size(), section.getAddress(), minMax.first,
                             minMax.second);
        }
        if(isNonZeroDataSection(extraInfo))
        {
            gtirb::ImageByteMap::const_range bytes =
                gtirb::getBytes(module.getImageByteMap(), section);
            storeDataSection(bytes, bytes.size(), section.getAddress(), minMax.first,
                             minMax.second);
        }
    }
    if(auto prog = souffle::ProgramFactory::newInstance("souffle_disasm_aarch64"))
    {
        loadInputs(prog, module);
        return prog;
    }
    return nullptr;
}

void AArch64Decoder::decodeSection(gtirb::ImageByteMap::const_range &sectionBytes, uint64_t size,
                              gtirb::Addr ea)
{
    auto buf = reinterpret_cast<const uint8_t *>(&*sectionBytes.begin());
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
            instructions.push_back(GtirbToDatalog::transformInstruction(CS_ARCH_ARM64, csHandle, op_dict, *insn));
            cs_free(insn, count);
        }
        ++ea;
        ++buf;
        --size;
    }
}
