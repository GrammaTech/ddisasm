//===- DlDecoder.cpp --------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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

#include "DlDecoder.h"

#include <souffle/CompiledSouffle.h>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

#include "AuxDataSchema.h"
#include "ExceptionDecoder.h"
#include "gtirb-builder/ElfReader.h"

namespace souffle
{
    template <class T>
    souffle::tuple &operator<<(souffle::tuple &t, const DlData<T> &data)
    {
        t << data.ea << data.content;
        return t;
    }

    souffle::tuple &operator<<(souffle::tuple &t, const ElfRelocation &ElfRelocation)
    {
        auto &[Addr, Type, Name, Addend] = ElfRelocation;
        t << Addr << Type << Name << Addend;
        return t;
    }

} // namespace souffle

std::string getFileFormatString(const gtirb::FileFormat format)
{
    switch(format)
    {
        case gtirb::FileFormat::COFF:
            return "COFF";
        case gtirb::FileFormat::ELF:
            return "ELF";
        case gtirb::FileFormat::PE:
            return "PE";
        case gtirb::FileFormat::IdaProDb32:
            return "IdaProDb32";
        case gtirb::FileFormat::IdaProDb64:
            return "IdaProDb64";
        case gtirb::FileFormat::XCOFF:
            return "XCOFF";
        case gtirb::FileFormat::MACHO:
            return "MACHO";
        case gtirb::FileFormat::RAW:
            return "RAW";
        case gtirb::FileFormat::Undefined:
        default:
            return "Undefined";
    }
}

void addSymbols(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    auto *rel = prog->getRelation("symbol");
    auto *SymbolInfo = module.getAuxData<gtirb::schema::ElfSymbolInfoAD>();
    for(auto &symbol : module.symbols())
    {
        souffle::tuple t(rel);
        if(auto address = symbol.getAddress())
            t << *address;
        else
            t << 0;
        ElfSymbolInfo Info = {0, "NOTYPE", "GLOBAL", "DEFAULT", 0};
        if(SymbolInfo)
        {
            auto found = SymbolInfo->find(symbol.getUUID());
            if(found == SymbolInfo->end())
                throw std::logic_error("Symbol " + symbol.getName()
                                       + " missing from elfSymbolInfo AuxData table");
            Info = found->second;
        }
        t << std::get<0>(Info) << std::get<1>(Info) << std::get<2>(Info) << std::get<4>(Info)
          << symbol.getName();
        rel->insert(t);
    }
}

void addSections(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    auto *rel = prog->getRelation("section_complete");
    auto *extraInfoTable = module.getAuxData<gtirb::schema::ElfSectionProperties>();
    if(!extraInfoTable)
        throw std::logic_error("missing elfSectionProperties AuxData table");

    for(auto &section : module.sections())
    {
        assert(section.getAddress() && "Section has no address.");
        assert(section.getSize() && "Section has non-calculable size.");

        souffle::tuple t(rel);
        auto found = extraInfoTable->find(section.getUUID());
        if(found == extraInfoTable->end())
            throw std::logic_error("Section " + section.getName()
                                   + " missing from elfSectionProperties AuxData table");
        SectionProperties &extraInfo = found->second;
        t << section.getName() << *section.getSize() << *section.getAddress()
          << std::get<0>(extraInfo) << std::get<1>(extraInfo);
        rel->insert(t);
    }
}

DlDecoder::DlDecoder()
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle); // == CS_ERR_OK
    cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

DlDecoder::~DlDecoder()
{
    cs_close(&this->csHandle);
}

souffle::SouffleProgram *DlDecoder::decode(gtirb::Module &module,
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
            for(auto &byteInterval : section.byte_intervals())
            {
                decodeSection(byteInterval);
                storeDataSection(byteInterval, minAddr, maxAddr);
            }
        }
        if(is_initialized)
        {
            for(auto &byteInterval : section.byte_intervals())
            {
                storeDataSection(byteInterval, minAddr, maxAddr);
            }
        }
    }
    if(auto prog = souffle::ProgramFactory::newInstance("souffle_disasm"))
    {
        loadInputs(prog, module);
        GtirbToDatalog::addToRelation<std::vector<std::string>>(prog, "option", DisasmOptions);
        return prog;
    }
    return nullptr;
}

void DlDecoder::decodeSection(const gtirb::ByteInterval &byteInterval)
{
    assert(byteInterval.getAddress() && "Failed to decode section without address.");

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
            instructions.push_back(GtirbToDatalog::transformInstruction(csHandle, op_dict, *insn));
            cs_free(insn, count);
        }
        ++ea;
        ++buf;
        --size;
    }
}

void DlDecoder::storeDataSection(const gtirb::ByteInterval &byteInterval, gtirb::Addr min_address,
                                 gtirb::Addr max_address)
{
    assert(byteInterval.getAddress() && "Failed to store section without address.");

    auto can_be_address = [min_address, max_address](gtirb::Addr num) {
        return ((num >= min_address) && (num <= max_address));
    };
    gtirb::Addr ea = byteInterval.getAddress().value();
    uint64_t size = byteInterval.getInitializedSize();
    auto buf = byteInterval.rawBytes<const uint8_t>();
    while(size > 0)
    {
        // store the byte
        uint8_t content_byte = *buf;
        data_bytes.push_back({ea, content_byte});

        // store the address
        if(size >= 8)
        {
            gtirb::Addr content(*((int64_t *)buf));
            if(can_be_address(content))
                data_addresses.push_back({ea, content});
        }
        ++ea;
        ++buf;
        --size;
    }
}

void DlDecoder::loadInputs(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    GtirbToDatalog::addToRelation<std::vector<std::string>>(
        prog, "binary_type", *module.getAuxData<gtirb::schema::BinaryType>());
    GtirbToDatalog::addToRelation<std::vector<std::string>>(
        prog, "binary_format", {getFileFormatString(module.getFileFormat())});

    if(gtirb::CodeBlock *block = module.getEntryPoint())
    {
        if(std::optional<gtirb::Addr> address = block->getAddress())
        {
            GtirbToDatalog::addToRelation<std::vector<gtirb::Addr>>(prog, "entry_point",
                                                                    {*address});
            module.setEntryPoint(nullptr);
            block->getByteInterval()->removeBlock(block);
        }
    }

    if(auto *Relocations = module.getAuxData<gtirb::schema::Relocations>())
    {
        GtirbToDatalog::addToRelation(prog, "relocation", *Relocations);
        module.removeAuxData<gtirb::schema::Relocations>();
    }

    GtirbToDatalog::addToRelation(prog, "instruction_complete", instructions);
    GtirbToDatalog::addToRelation(prog, "address_in_data", data_addresses);
    GtirbToDatalog::addToRelation(prog, "data_byte", data_bytes);
    GtirbToDatalog::addToRelation(prog, "invalid_op_code", invalids);
    GtirbToDatalog::addToRelation(prog, "op_regdirect", op_dict.regTable);
    GtirbToDatalog::addToRelation(prog, "op_immediate", op_dict.immTable);
    GtirbToDatalog::addToRelation(prog, "op_indirect", op_dict.indirectTable);

    addSymbols(prog, module);
    addSections(prog, module);

    ExceptionDecoder excDecoder(module);
    excDecoder.addExceptionInformation(prog);
}
