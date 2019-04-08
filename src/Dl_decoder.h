//===- Dl_decoder.h ---------------------------------------------*- C++ -*-===//
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

#ifndef SRC_DL_DECODER_H_
#define SRC_DL_DECODER_H_
#include "Dl_instruction.h"
#include "Dl_operator.h"
#include "Dl_operator_table.h"

#include <capstone/capstone.h>
#include <cstdint>
#include <vector>

template <class Content>
struct Dl_data
{
public:
    int64_t ea;
    Content content;
    Dl_data(int64_t ea, Content content) : ea(ea), content(content)
    {
    }
    std::string result_tabs();
};

class Dl_decoder
{
    csh csHandle;

public:
    Dl_operator_table op_dict;
    std::vector<Dl_instruction> instructions;
    std::vector<int64_t> invalids;
    std::vector<Dl_data<int64_t>> data;
    std::vector<Dl_data<unsigned char>> data_bytes;
    Dl_decoder();
    void decode_section(char* buff, uint64_t size, int64_t ea);
    std::string getRegisterName(unsigned int reg);
    Dl_instruction transformInstruction(cs_insn& insn);
    Dl_operator buildOperand(const cs_x86_op& op);
    void store_data_section(char* buff, uint64_t size, int64_t ea, uint64_t min_address,
                            uint64_t max_address);

    void print_instructions(std::ofstream& fbuf);
    void print_operators_of_type(operator_type type, std::ofstream& fbuf);
    void print_invalids(std::ofstream& fbuf);
    void print_data(std::ofstream& fbuf);
    void print_data_bytes(std::ofstream& fbuf);
};

#endif /* SRC_DL_DECODER_H_ */
