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
#include "Dl_operator_table.h"

#include <vector>

struct Dl_instruction
{
    uint64_t address;
    long size;
    std::string prefix;
    std::string name;
    std::vector<uint64_t> op_codes;
    uint8_t immediateOffset;
    uint8_t displacementOffset;
};

template <class Content>
struct Dl_data
{
    uint64_t ea;
    Content content;
};

class Dl_decoder
{
private:
    csh csHandle;
    Dl_operator_table op_dict;
    std::vector<Dl_instruction> instructions;
    std::vector<uint64_t> invalids;
    std::vector<Dl_data<uint64_t>> data_addresses;
    std::vector<Dl_data<unsigned char>> data_bytes;
    void decode_section(const uint8_t* buff, uint64_t size, uint64_t ea);
    std::string getRegisterName(unsigned int reg);
    Dl_instruction transformInstruction(cs_insn& insn);
    std::variant<ImmOp, RegOp, IndirectOp> buildOperand(const cs_x86_op& op);
    void store_data_section(const uint8_t* buff, uint64_t size, uint64_t ea, uint64_t min_address,
                            uint64_t max_address);
    void loadInputs(souffle::SouffleProgram* prog, gtirb::Module& module);
    template <typename T>
    void addRelation(souffle::SouffleProgram* prog, const std::string& name,
                     const std::vector<T>& data);
    template <typename T>
    void addMapToRelation(souffle::SouffleProgram* prog, const std::string& name,
                          const std::map<T, uint64_t>& data);
    std::string getFileFormatString(gtirb::FileFormat format);

public:
    Dl_decoder();
    souffle::SouffleProgram* decode(gtirb::Module& module);
};

#endif /* SRC_DL_DECODER_H_ */
