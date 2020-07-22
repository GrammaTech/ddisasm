//===- ArmDecoder.cpp -----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
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
#include "ArmDecoder.h"

void ArmDecoder::decodeSection(const gtirb::ByteInterval &byteInterval)
{
    gtirb::Addr ea = byteInterval.getAddress().value();
    uint64_t size = byteInterval.getInitializedSize();
    auto decode_in_mode = [&byteInterval, this](uint64_t size, gtirb::Addr ea, bool thumb) {
        auto buf = byteInterval.rawBytes<const unsigned char>();
        size_t InsnSize = 4;
        if(thumb)
        {
            InsnSize = 2;
            ea++;
        }
        while(size >= InsnSize)
        {
            size_t increment = InsnSize;
            cs_insn *insn;
            size_t count =
                cs_disasm(CsHandle.getHandle(), buf, size, static_cast<uint64_t>(ea), 1, &insn);
            if(count == 0)
            {
                invalids.push_back(ea);
            }
            else
            {
                instructions.push_back(
                    GtirbToDatalog::transformInstruction(CsHandle, op_dict, *insn));
                increment = insn->size;
            }
            cs_free(insn, count);
            ea += increment;
            buf += increment;
            size -= increment;
        }
    };
    cs_option(CsHandle.getHandle(), CS_OPT_MODE, CS_MODE_ARM);
    decode_in_mode(size, ea, false);
    cs_option(CsHandle.getHandle(), CS_OPT_MODE, CS_MODE_THUMB);
    decode_in_mode(size, ea, true);
}
