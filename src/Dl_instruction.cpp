//===- Dl_instruction.cpp ---------------------------------------*- C++ -*-===//
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

#include "Dl_instruction.h"
#include <sstream>

std::string Dl_instruction::result_tabs()
{
    std::ostringstream o;
    o << address << "\t" << size << "\t" << prefix << "\t" << name;
    for(size_t i = 0; i < 4; ++i)
    {
        if(i < op_codes.size())
            o << "\t" << op_codes[i];
        else
            o << "\t" << 0;
    }
    o << "\t" << static_cast<int16_t>(immediateOffset) << "\t"
      << static_cast<int16_t>(displacementOffset);
    return o.str();
}
