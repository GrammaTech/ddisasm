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
#ifndef SRC_ELF_LOADER_H_
#define SRC_ELF_LOADER_H_

#include "DatalogLoader.h"

#include "ExceptionDecoder.h"

// FIXME:
#include "Arm64Decoder.h"
#include "X64Decoder.h"

class ElfSymbolDecoder : public SymbolDecoder
{
public:
    using Symbol = SymbolDecoder::Symbol;

    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

private:
    std::vector<Symbol> Symbols;
};

class ElfExceptionDecoder : public GtirbDecoder
{
public:
    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

private:
    std::unique_ptr<ExceptionDecoder> Decoder;
};

class ElfX64Loader : public DatalogLoader
{
public:
    ElfX64Loader() : DatalogLoader("souffle_disasm_x64")
    {
        add<FormatDecoder>();
        add<SectionDecoder>();
        add<X64Decoder>();
        add<DataDecoder>();
        add<ElfSymbolDecoder>();
        add<ElfExceptionDecoder>();
    }
};

class ElfArm64Loader : public DatalogLoader
{
public:
    ElfArm64Loader() : DatalogLoader("souffle_disasm_arm64")
    {
        add<FormatDecoder>();
        add<SectionDecoder>();
        add<Arm64Decoder>();
        add<DataDecoder>();
        add<ElfSymbolDecoder>();
        add<ElfExceptionDecoder>();
    }
};

#endif /* SRC_ELF_LOADER_H_ */
