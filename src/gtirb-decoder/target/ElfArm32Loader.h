//===- ElfARM32Loader.h -------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_TARGET_ELFARM32LOADER_H_
#define SRC_GTIRB_DECODER_TARGET_ELFARM32LOADER_H_

#include "../CompositeLoader.h"
#include "../arch/Arm32Loader.h"
#include "../core/DataLoader.h"
#include "../core/ModuleLoader.h"
#include "../core/SectionLoader.h"
#include "../format/ElfLoader.h"

class ElfArm32Loader : public CompositeLoader
{
public:
    ElfArm32Loader() : CompositeLoader("souffle_disasm_arm32")
    {
        add(ModuleLoader);
        add(SectionLoader);
        add<Arm32Loader>();
        add<DataLoader>(DataLoader::Pointer::DWORD);
        add(ElfSymbolLoader);
        add(ElfExceptionLoader);
    }
};

#endif // SRC_GTIRB_DECODER_TARGET_ELFARM32LOADER_H_
