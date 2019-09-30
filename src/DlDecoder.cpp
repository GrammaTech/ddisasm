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
#include "BinaryReader.h"
#include "ExceptionDecoder.h"
#include "GtirbZeroBuilder.h"
// FIXME: remove once section properties are generic
#include <elf.h>
#include <souffle/CompiledSouffle.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;

DlDecoder::DlDecoder()
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle); // == CS_ERR_OK
    cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

souffle::SouffleProgram *DlDecoder::decode(gtirb::Module &module)
{
    auto isNonZeroDataSection = [](const SectionProperties &s) {
        uint64_t type = std::get<0>(s);
        uint64_t flags = std::get<1>(s);
        bool is_allocated = flags & SHF_ALLOC;
        bool is_not_executable = !(flags & SHF_EXECINSTR);
        // SHT_NOBITS is not considered here because it is for data sections but without initial
        // data (zero initialized)
        bool is_non_zero_program_data = type == SHT_PROGBITS || type == SHT_INIT_ARRAY
                                        || type == SHT_FINI_ARRAY || type == SHT_PREINIT_ARRAY;
        return is_allocated && is_not_executable && is_non_zero_program_data;
    };
    auto isExeSection = [](const SectionProperties &s) {
        uint64_t flags = std::get<1>(s);
        return flags & SHF_EXECINSTR;
    };

    auto minMax = module.getImageByteMap().getAddrMinMax();
    auto *extraInfoTable =
        module.getAuxData<std::map<gtirb::UUID, SectionProperties>>("elfSectionProperties");
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
            decode_section(bytes, bytes.size(), section.getAddress());
        }
        if(isNonZeroDataSection(extraInfo))
        {
            gtirb::ImageByteMap::const_range bytes =
                gtirb::getBytes(module.getImageByteMap(), section);
            store_data_section(bytes, bytes.size(), section.getAddress(), minMax.first,
                               minMax.second);
        }
    }
    if(auto prog = souffle::ProgramFactory::newInstance("souffle_disasm"))
    {
        loadInputs(prog, module);
        return prog;
    }
    return nullptr;
}

void DlDecoder::decode_section(gtirb::ImageByteMap::const_range &sectionBytes, uint64_t size,
                               gtirb::Addr ea)
{
    auto buf = reinterpret_cast<const uint8_t *>(&*sectionBytes.begin());
    while(size > 0)
    {
        cs_insn *insn;
        size_t count = cs_disasm(this->csHandle, buf, size, static_cast<uint64_t>(ea), 1, &insn);
        if(count == 0)
        {
            invalids.push_back(ea);
        }
        else
        {
            instructions.push_back(this->transformInstruction(*insn));
            cs_free(insn, count);
        }
        ++ea;
        ++buf;
        --size;
    }
}

void DlDecoder::store_data_section(gtirb::ImageByteMap::const_range &sectionBytes, uint64_t size,
                                   gtirb::Addr ea, gtirb::Addr min_address, gtirb::Addr max_address)
{
    auto can_be_address = [min_address, max_address](gtirb::Addr num) {
        return ((num >= min_address) && (num <= max_address));
    };
    auto buf = reinterpret_cast<const uint8_t *>(&*sectionBytes.begin());
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

std::string str_toupper(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
    return s;
}

std::string DlDecoder::getRegisterName(unsigned int reg)
{
    if(reg == X86_REG_INVALID)
        return "NONE";
    std::string name = str_toupper(cs_reg_name(this->csHandle, reg));
    return name;
}

DlInstruction DlDecoder::transformInstruction(cs_insn &insn)
{
    std::vector<uint64_t> op_codes;
    std::string prefix_name = str_toupper(insn.mnemonic);
    std::string prefix, name;
    size_t pos = prefix_name.find(' ');
    if(pos != std::string::npos)
    {
        prefix = prefix_name.substr(0, pos);
        name = prefix_name.substr(pos + 1);
    }
    else
    {
        prefix = "";
        name = prefix_name;
    }

    auto &detail = insn.detail->x86;
    if(name != "NOP")
    {
        auto opCount = detail.op_count;
        // skip the destination operand
        for(int i = 0; i < opCount; i++)
        {
            const auto &op = detail.operands[i];
            uint64_t index = op_dict.add(this->buildOperand(op));
            op_codes.push_back(index);
        }
        // we put the destination operand at the end
        if(opCount > 0)
            std::rotate(op_codes.begin(), op_codes.begin() + 1, op_codes.end());
    }
    return {insn.address,
            insn.size,
            prefix,
            name,
            op_codes,
            detail.encoding.imm_offset,
            detail.encoding.disp_offset};
}

std::variant<ImmOp, RegOp, IndirectOp> DlDecoder::buildOperand(const cs_x86_op &op)
{
    switch(op.type)
    {
        case X86_OP_REG:
            return getRegisterName(op.reg);
        case X86_OP_IMM:
            return op.imm;
        case X86_OP_MEM:
        {
            IndirectOp I = {getRegisterName(op.mem.segment),
                            getRegisterName(op.mem.base),
                            getRegisterName(op.mem.index),
                            op.mem.scale,
                            op.mem.disp,
                            op.size * 8};
            return I;
        }
        case X86_OP_INVALID:
        default:
            throw std::logic_error("Found invalid operand");
    }
}

souffle::tuple &operator<<(souffle::tuple &t, const gtirb::Addr &a)
{
    t << static_cast<uint64_t>(a);
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const DlInstruction &inst)
{
    t << inst.address << inst.size << inst.prefix << inst.name;
    for(size_t i = 0; i < 4; ++i)
    {
        if(i < inst.op_codes.size())
            t << inst.op_codes[i];
        else
            t << 0;
    }
    t << inst.immediateOffset << inst.displacementOffset;
    return t;
}

template <class T>
souffle::tuple &operator<<(souffle::tuple &t, const DlData<T> &data)
{
    t << data.ea << data.content;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const InitialAuxData::Relocation &relocation)
{
    t << relocation.address << relocation.type << relocation.name << relocation.addend;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const InitialAuxData::Symbol &symbol)
{
    t << symbol.address << symbol.size << symbol.type << symbol.scope << symbol.sectionIndex
      << symbol.name;
    return t;
}

template <typename T>
void DlDecoder::addToRelation(souffle::SouffleProgram *prog, const std::string &name, const T &data)
{
    auto *rel = prog->getRelation(name);
    for(const auto &elt : data)
    {
        souffle::tuple t(rel);
        t << elt;
        rel->insert(t);
    }
}

std::string DlDecoder::getFileFormatString(gtirb::FileFormat format)
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

void DlDecoder::addSymbols(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    auto *rel = prog->getRelation("symbol");
    auto *extraInfoTable =
        module.getAuxData<std::map<gtirb::UUID, ExtraSymbolInfo>>("extraSymbolInfo");
    for(auto &symbol : module.symbols())
    {
        souffle::tuple t(rel);
        if(auto address = symbol.getAddress())
            t << *address;
        else
            t << 0;
        auto found = extraInfoTable->find(symbol.getUUID());
        if(found == extraInfoTable->end())
            throw std::logic_error("Symbol " + symbol.getName()
                                   + " missing from extraSymbolInfo AuxData table");

        ExtraSymbolInfo &extraInfo = found->second;
        t << extraInfo.size << extraInfo.type << extraInfo.scope << extraInfo.sectionIndex
          << symbol.getName();
        rel->insert(t);
    }
}

void DlDecoder::addSections(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    auto *rel = prog->getRelation("section_complete");
    auto *extraInfoTable =
        module.getAuxData<std::map<gtirb::UUID, SectionProperties>>("elfSectionProperties");
    for(auto &section : module.sections())
    {
        souffle::tuple t(rel);
        auto found = extraInfoTable->find(section.getUUID());
        if(found == extraInfoTable->end())
            throw std::logic_error("Section " + section.getName()
                                   + " missing from elfSectionProperties AuxData table");
        SectionProperties &extraInfo = found->second;
        t << section.getName() << section.getSize() << section.getAddress()
          << std::get<0>(extraInfo) << std::get<1>(extraInfo);
        rel->insert(t);
    }
}

void DlDecoder::loadInputs(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    addToRelation(prog, "binary_type", *module.getAuxData<std::vector<std::string>>("binaryType"));
    addToRelation<std::vector<std::string>>(prog, "binary_format",
                                            {getFileFormatString(module.getFileFormat())});
    addToRelation<std::vector<gtirb::Addr>>(
        prog, "entry_point", *module.getAuxData<std::vector<gtirb::Addr>>("entryPoint"));
    addToRelation(prog, "relocation",
                  *module.getAuxData<std::set<InitialAuxData::Relocation>>("relocations"));
    module.removeAuxData("relocation");
    addToRelation(prog, "instruction_complete", instructions);
    addToRelation(prog, "address_in_data", data_addresses);
    addToRelation(prog, "data_byte", data_bytes);
    addToRelation(prog, "invalid_op_code", invalids);
    addToRelation(prog, "op_regdirect", op_dict.regTable);
    addToRelation(prog, "op_immediate", op_dict.immTable);
    addToRelation(prog, "op_indirect", op_dict.indirectTable);
    addSymbols(prog, module);
    module.removeAuxData("extraSymbolInfo");
    addSections(prog, module);
    ExceptionDecoder excDecoder(module);
    excDecoder.addExceptionInformation(prog);
}