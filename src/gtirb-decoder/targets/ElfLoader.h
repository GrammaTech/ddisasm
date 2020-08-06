//===- ElfLoader.h ----------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_TARGETS_ELFLOADER_H_
#define SRC_GTIRB_DECODER_TARGETS_ELFLOADER_H_

#include <string>

#include "../CompositeLoader.h"
#include "../Relations.h"
#include "ExceptionDecoder.h"

void ElfSymbolLoader(const gtirb::Module& Module, DatalogProgram& Program);

void ElfExceptionLoader(const gtirb::Module& Module, DatalogProgram& Program);

namespace relations
{
    struct Relocation
    {
        uint64_t Address;
        std::string Type;
        std::string Name;
        int64_t Addend;
    };
} // namespace relations

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const relations::Relocation& Rel);
}

#endif // SRC_GTIRB_DECODER_TARGETS_ELFLOADER_H_
