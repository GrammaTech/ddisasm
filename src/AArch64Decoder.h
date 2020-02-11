//===- AArch64Decoder.h -----------------------------------------*- C++ -*-===//
//
//  Copyright (c) 2020, The Binrat Developers.
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
//===----------------------------------------------------------------------===//

#ifndef SRC_AARCH64_DECODER_H_
#define SRC_AARCH64_DECODER_H_
#include <capstone/capstone.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>
#include "DlDecoder.h"
#include "DatalogUtils.h"
#include "DlOperandTable.h"
#include <vector>



class AArch64Decoder : public DlDecoder
{
public:
    AArch64Decoder();
    ~AArch64Decoder();
    souffle::SouffleProgram* decode(gtirb::Module& module);
    void decodeSection(gtirb::ImageByteMap::const_range& sectionBytes, uint64_t size,
                       gtirb::Addr ea);
};

#endif /* SRC_AARCH64_DECODER_H_ */
