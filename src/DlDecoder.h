//===- DlDecoder.h ----------------------------------------------*- C++ -*-===//
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
#include "DatalogUtils.h"
#include "DlOperandTable.h"

#include <vector>

template <class Content>
struct DlData
{
    gtirb::Addr ea;
    Content content;
};

class DlDecoder
{
private:
    csh csHandle;
    DlOperandTable op_dict;
    std::vector<DlInstruction> instructions;
    std::vector<gtirb::Addr> invalids;
    std::vector<DlData<gtirb::Addr>> data_addresses;
    std::vector<DlData<unsigned char>> data_bytes;
    void decodeSection(const gtirb::ByteInterval& byteInterval);
    void loadInputs(souffle::SouffleProgram* prog, gtirb::Module& module);
    void storeDataSection(const gtirb::ByteInterval& byteInterval, gtirb::Addr min_address,
                          gtirb::Addr max_address);

public:
    DlDecoder();
    ~DlDecoder();
    souffle::SouffleProgram* decode(gtirb::Module& module,
                                    const std::vector<std::string>& DisasmOptions);
};

#endif /* SRC_DL_DECODER_H_ */
