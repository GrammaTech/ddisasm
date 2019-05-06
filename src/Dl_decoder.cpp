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
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;

Dl_decoder::Dl_decoder()
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle); // == CS_ERR_OK
    cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

void Dl_decoder::decode_section(char* buf, uint64_t size, int64_t ea)
{
    while(size > 0)
    {
        cs_insn* insn;
        size_t count = cs_disasm(this->csHandle, (const uint8_t*)buf, size, ea, 1, &insn);
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

Dl_instruction Dl_decoder::transformInstruction(cs_insn& insn)
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

    auto& detail = insn.detail->x86;
    if(name != "NOP")
    {
        auto opCount = detail.op_count;
        // skip the destination operand
        for(int i = 1; i < opCount; i++)
        {
            const auto& op = detail.operands[i];
            int64_t index = op_dict.add(this->buildOperand(op));
            op_codes.push_back(index);
        }
        // we put the destination operand at the end
        if(opCount > 0)
        {
            const auto& op = detail.operands[0];
            int64_t index = op_dict.add(this->buildOperand(op));
            op_codes.push_back(index);
        }
    }
    // FIXME what about the prefix?
    return Dl_instruction(insn.address, insn.size, prefix, name, op_codes,
                          detail.encoding.imm_offset, detail.encoding.disp_offset);
}

Dl_operator Dl_decoder::buildOperand(const cs_x86_op& op)
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

bool can_be_address(uint64_t num, uint64_t min_address, uint64_t max_address)
{
    return ((num >= min_address)
            && (num <= max_address)); // absolute address
                                      //     ||  (num+min_address<=max_address); //offset
}

void Dl_decoder::store_data_section(char* buf, uint64_t size, int64_t ea, uint64_t min_address,
                                    uint64_t max_address)
{
    while(size > 0)
    {
        // store the byte
        unsigned char content_byte = *buf;
        data_bytes.push_back(Dl_data<unsigned char>(ea, content_byte));

        // store the address
        if(size >= 8)
        {
            uint64_t content = *((int64_t*)buf);
            if(can_be_address(content, min_address, max_address))
                data.push_back(Dl_data<int64_t>(ea, content));
        }
        ++ea;
        ++buf;
        --size;
    }
}

void Dl_decoder::print_instructions(std::ofstream& fbuf)
{
    for(auto instruction : instructions)
    {
        fbuf << instruction.result_tabs() << endl;
    }
}
void Dl_decoder::print_operators_of_type(operator_type type, ofstream& fbuf)
{
    op_dict.print_operators_of_type(type, fbuf);
}
void Dl_decoder::print_invalids(ofstream& fbuf)
{
    for(auto invalid : invalids)
    {
        fbuf << invalid << endl;
    }
}

void Dl_decoder::print_data(ofstream& fbuf)
{
    for(auto data_item : data)
    {
        fbuf << data_item.result_tabs() << endl;
    }
}
void Dl_decoder::print_data_bytes(ofstream& fbuf)
{
    for(auto data_item : data_bytes)
    {
        fbuf << data_item.result_tabs() << endl;
    }
}

template <class Content>
std::string Dl_data<Content>::result_tabs()
{
    ostringstream o;
    o << ea << '\t' << static_cast<int64_t>(content);
    return o.str();
}
