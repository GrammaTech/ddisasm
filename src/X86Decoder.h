//===- X86Decoder.h ---------------------------------------------*- C++ -*-===//
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

#ifndef SRC_X86_DECODER_H_
#define SRC_X86_DECODER_H_

#include <capstone/capstone.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>
#include "DatalogUtils.h"
#include "DlOperandTable.h"
#include "DlDecoder.h"

#include <vector>
class X86Decoder : public DlDecoder
{
public:
    X86Decoder();
    virtual ~X86Decoder();
    souffle::SouffleProgram* decode(gtirb::Module& module);
    void decodeSection(const gtirb::ByteInterval& byteInterval);
    cs_arch getArch() const override {
        return CS_ARCH_X86;
    }
    cs_mode getMode() const override {
        return CS_MODE_64;
    }
};

#endif /* SRC_X86_DECODER_H_ */
