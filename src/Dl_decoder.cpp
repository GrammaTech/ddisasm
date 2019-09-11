//===- Dl_decoder.cpp -------------------------------------------*- C++ -*-===//
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

#include "Dl_decoder.h"
#include <souffle/CompiledSouffle.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include "BinaryReader.h"
#include "Elf_reader.h"
#include "ExceptionDecoder.h"

using namespace std;

Dl_decoder::Dl_decoder()
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle); // == CS_ERR_OK
    cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

souffle::SouffleProgram *Dl_decoder::decode(gtirb::Module &module)
{
    auto isNonZeroDataSection = [](const InitialAuxData::Section &s) {
        bool is_allocated = s.flags & SHF_ALLOC;
        bool is_not_executable = !(s.flags & SHF_EXECINSTR);
        // SHT_NOBITS is not considered here because it is for data sections but without initial
        // data (zero initialized)
        bool is_non_zero_program_data = s.type == SHT_PROGBITS || s.type == SHT_INIT_ARRAY
                                        || s.type == SHT_FINI_ARRAY || s.type == SHT_PREINIT_ARRAY;
        return is_allocated && is_not_executable && is_non_zero_program_data;
    };
    auto isExeSection = [](const InitialAuxData::Section &s) { return s.flags & SHF_EXECINSTR; };

    auto minMax = module.getImageByteMap().getAddrMinMax();
    for(const auto &sectionInfo :
        *module.getAuxData<std::vector<InitialAuxData::Section>>("section_complete"))
    {
        if(isExeSection(sectionInfo))
        {
            auto section = module.findSection(sectionInfo.name);
            if(section != module.section_by_name_end())
            {
                gtirb::ImageByteMap::const_range bytes =
                    gtirb::getBytes(module.getImageByteMap(), *section);
                decode_section(reinterpret_cast<const uint8_t *>(&*bytes.begin()), bytes.size(),
                               static_cast<uint64_t>(section->getAddress()));
            }
        }
        if(isNonZeroDataSection(sectionInfo))
        {
            auto section = module.findSection(sectionInfo.name);
            if(section != module.section_by_name_end())
            {
                gtirb::ImageByteMap::const_range bytes =
                    gtirb::getBytes(module.getImageByteMap(), *section);
                store_data_section(reinterpret_cast<const uint8_t *>(&*bytes.begin()), bytes.size(),
                                   static_cast<uint64_t>(section->getAddress()),
                                   static_cast<uint64_t>(minMax.first),
                                   static_cast<uint64_t>(minMax.second));
            }
        }
    }
    if(auto prog = souffle::ProgramFactory::newInstance("souffle_disasm"))
    {
        loadInputs(prog, module);
        return prog;
    }
    return nullptr;
}

void Dl_decoder::decode_section(const uint8_t *buf, uint64_t size, int64_t ea)
{
    while(size > 0)
    {
        cs_insn *insn;
        size_t count = cs_disasm(this->csHandle, buf, size, ea, 1, &insn);
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

void Dl_decoder::store_data_section(const uint8_t *buf, uint64_t size, int64_t ea,
                                    uint64_t min_address, uint64_t max_address)
{
    auto can_be_address = [min_address, max_address](uint64_t num) {
        return ((num >= min_address) && (num <= max_address));
    };

    while(size > 0)
    {
        // store the byte
        uint8_t content_byte = *buf;
        data_bytes.push_back(Dl_data<uint8_t>(ea, content_byte));

        // store the address
        if(size >= 8)
        {
            uint64_t content = *((int64_t *)buf);
            if(can_be_address(content))
                data_addresses.push_back(Dl_data<int64_t>(ea, content));
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

std::string Dl_decoder::getRegisterName(unsigned int reg)
{
    if(reg == X86_REG_INVALID)
        return "NONE";
    std::string name = str_toupper(cs_reg_name(this->csHandle, reg));
    return name;
}

Dl_instruction Dl_decoder::transformInstruction(cs_insn &insn)
{
    std::vector<int64_t> op_codes;
    std::string prefix_name = insn.mnemonic;
    std::string prefix, name;
    size_t pos = prefix_name.find(' ');
    if(pos != std::string::npos)
    {
        prefix = str_toupper(prefix_name.substr(0, pos));
        name = str_toupper(prefix_name.substr(pos + 1, prefix_name.length() - (pos + 1)));
    }
    else
    {
        prefix = "";
        name = str_toupper(prefix_name);
    }

    auto &detail = insn.detail->x86;
    if(name != "NOP")
    {
        auto opCount = detail.op_count;
        // skip the destination operand
        for(int i = 1; i < opCount; i++)
        {
            const auto &op = detail.operands[i];
            int64_t index = op_dict.add(this->buildOperand(op));
            op_codes.push_back(index);
        }
        // we put the destination operand at the end
        if(opCount > 0)
        {
            const auto &op = detail.operands[0];
            int64_t index = op_dict.add(this->buildOperand(op));
            op_codes.push_back(index);
        }
    }
    return Dl_instruction(insn.address, insn.size, prefix, name, op_codes,
                          detail.encoding.imm_offset, detail.encoding.disp_offset);
}

Dl_operator Dl_decoder::buildOperand(const cs_x86_op &op)
{
    Dl_operator curr_op;
    switch(op.type)
    {
        case X86_OP_REG:
            curr_op.type = operator_type::REG;
            curr_op.reg1 = getRegisterName(op.reg);
            break;
        case X86_OP_IMM:
            curr_op.type = operator_type::IMMEDIATE;
            curr_op.offset = op.imm;
            break;
        case X86_OP_MEM:
            curr_op.type = operator_type::INDIRECT;
            curr_op.reg1 = getRegisterName(op.mem.segment);
            curr_op.reg2 = getRegisterName(op.mem.base);
            curr_op.reg3 = getRegisterName(op.mem.index);
            curr_op.offset = op.mem.disp;
            curr_op.multiplier = op.mem.scale;
            break;
        case X86_OP_INVALID:
            std::cerr << "invalid operand\n";
            exit(1);
    }
    // size in bits
    curr_op.size = op.size * 8;
    return curr_op;
}

souffle::tuple &operator<<(souffle::tuple &t, const Dl_instruction &inst)
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
souffle::tuple &operator<<(souffle::tuple &t, const Dl_data<T> &data)
{
    t << data.ea << static_cast<int64_t>(data.content);
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const std::pair<Dl_operator, int64_t> &pair)
{
    auto &[op, id] = pair;
    switch(op.type)
    {
        case NONE:
        default:
            break;
        case REG:
            t << id << op.reg1;
            break;
        case IMMEDIATE:
            t << id << op.offset;
            break;
        case INDIRECT:
            t << id << op.reg1 << op.reg2 << op.reg3 << op.multiplier << op.offset << op.size;
            break;
    }

    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const InitialAuxData::Section &section)
{
    t << section.name << section.size << section.address << section.type << section.flags;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const InitialAuxData::Symbol &symbol)
{
    t << symbol.address << symbol.size << symbol.type << symbol.scope << symbol.sectionIndex
      << symbol.name;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const InitialAuxData::Relocation &relocation)
{
    t << relocation.address << relocation.type << relocation.name << relocation.addend;
    return t;
}

template <typename T>
void Dl_decoder::addRelation(souffle::SouffleProgram *prog, const std::string &name,
                             const std::vector<T> &data)
{
    auto *rel = prog->getRelation(name);
    for(const auto elt : data)
    {
        souffle::tuple t(rel);
        t << elt;
        rel->insert(t);
    }
}

std::string Dl_decoder::getFileFormatString(gtirb::FileFormat format)
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
void Dl_decoder::loadInputs(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    addRelation<std::string>(prog, "binary_type",
                             *module.getAuxData<std::vector<std::string>>("binary_type"));
    addRelation<std::string>(prog, "binary_format", {getFileFormatString(module.getFileFormat())});
    addRelation<uint64_t>(prog, "entry_point",
                          *module.getAuxData<std::vector<uint64_t>>("entry_point"));
    addRelation(prog, "section_complete",
                *module.getAuxData<std::vector<InitialAuxData::Section>>("section_complete"));
    addRelation(prog, "symbol", *module.getAuxData<std::vector<InitialAuxData::Symbol>>("symbol"));
    addRelation(prog, "relocation",
                *module.getAuxData<std::vector<InitialAuxData::Relocation>>("relocation"));
    addRelation(prog, "instruction_complete", instructions);
    addRelation(prog, "address_in_data", data_addresses);
    addRelation(prog, "data_byte", data_bytes);
    addRelation(prog, "invalid_op_code", invalids);
    addRelation(prog, "op_regdirect", op_dict.get_operators_of_type(operator_type::REG));
    addRelation(prog, "op_immediate", op_dict.get_operators_of_type(operator_type::IMMEDIATE));
    addRelation(prog, "op_indirect", op_dict.get_operators_of_type(operator_type::INDIRECT));

    ExceptionDecoder excDecoder(module);
    excDecoder.addExceptionInformation(prog);
}