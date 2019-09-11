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
#include <capstone/capstone.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>
#include "Dl_operator.h"
#include "Dl_operator_table.h"

#include <vector>

class Dl_instruction
{
public:
    int64_t address;
    long size;
    std::string prefix;
    std::string name;
    std::vector<int64_t> op_codes;
    int8_t immediateOffset;
    int8_t displacementOffset;

    Dl_instruction()
        : address(0),
          size(0),
          prefix(),
          name(),
          op_codes(),
          immediateOffset(),
          displacementOffset(){};

    Dl_instruction(int64_t address, long size, const std::string& prefix, const std::string& name,
                   std::vector<int64_t> op_codes, int8_t immediateOffset, int8_t displacementOffset)
        : address(address),
          size(size),
          prefix(prefix),
          name(name),
          op_codes(op_codes),
          immediateOffset(immediateOffset),
          displacementOffset(displacementOffset){};
};

template <class Content>
struct Dl_data
{
public:
    int64_t ea;
    Content content;
    Dl_data(int64_t ea, Content content) : ea(ea), content(content)
    {
    }
};

class Dl_decoder
{
private:
    csh csHandle;
    Dl_operator_table op_dict;
    std::vector<Dl_instruction> instructions;
    std::vector<int64_t> invalids;
    std::vector<Dl_data<int64_t>> data_addresses;
    std::vector<Dl_data<unsigned char>> data_bytes;
    void decode_section(const uint8_t* buff, uint64_t size, int64_t ea);
    std::string getRegisterName(unsigned int reg);
    Dl_instruction transformInstruction(cs_insn& insn);
    Dl_operator buildOperand(const cs_x86_op& op);
    void store_data_section(const uint8_t* buff, uint64_t size, int64_t ea, uint64_t min_address,
                            uint64_t max_address);
    void loadInputs(souffle::SouffleProgram* prog, gtirb::Module& module);
    template <typename T>
    void addRelation(souffle::SouffleProgram* prog, const std::string& name,
                     const std::vector<T>& data);
    std::string getFileFormatString(gtirb::FileFormat format);

public:
    Dl_decoder();
    souffle::SouffleProgram* decode(gtirb::Module& module);
};

#endif /* SRC_DL_DECODER_H_ */
