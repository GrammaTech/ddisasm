//===- PeLoader.h -----------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_FORMAT_PELOADER_H_
#define SRC_GTIRB_DECODER_FORMAT_PELOADER_H_

#include <string>
#include <tuple>

#include <gtirb/gtirb.hpp>

#include "../../gtirb-builder/PeReader.h"
#include "../CompositeLoader.h"
#include "../Relations.h"

void PeSymbolLoader(const gtirb::Module &Module, DatalogProgram &Program);

namespace souffle
{
    souffle::tuple &operator<<(souffle::tuple &t, const DataDirectory &DataDirectory);

    souffle::tuple &operator<<(souffle::tuple &t, const ImportEntry &ImportEntry);
} // namespace souffle

#endif // SRC_GTIRB_DECODER_FORMAT_PELOADER_H_
