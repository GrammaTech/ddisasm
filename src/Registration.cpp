//===- Registration.cpp -----------------------------------------*- C++ -*-===//
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
#include "Registration.h"

#include "AuxDataSchema.h"

#include "gtirb-decoder/DatalogProgram.h"
#include "gtirb-decoder/target/ElfArm64Loader.h"
#include "gtirb-decoder/target/ElfX64Loader.h"
#include "gtirb-decoder/target/ElfX86Loader.h"
#include "gtirb-decoder/target/PeX64Loader.h"
#include "gtirb-decoder/target/PeX86Loader.h"

void registerAuxDataTypes()
{
    using namespace gtirb::schema;
    gtirb::AuxDataContainer::registerAuxDataType<Alignment>();
    gtirb::AuxDataContainer::registerAuxDataType<Comments>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionBlocks>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionNames>();
    gtirb::AuxDataContainer::registerAuxDataType<Padding>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolForwarding>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolInfoAD>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolTabIdxInfoAD>();
    gtirb::AuxDataContainer::registerAuxDataType<DynamicEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<BinaryType>();
    gtirb::AuxDataContainer::registerAuxDataType<Sccs>();
    gtirb::AuxDataContainer::registerAuxDataType<Relocations>();
    gtirb::AuxDataContainer::registerAuxDataType<Encodings>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSectionIndex>();
    gtirb::AuxDataContainer::registerAuxDataType<CfiDirectives>();
    gtirb::AuxDataContainer::registerAuxDataType<Libraries>();
    gtirb::AuxDataContainer::registerAuxDataType<LibraryPaths>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolicExpressionSizes>();
    gtirb::AuxDataContainer::registerAuxDataType<DdisasmVersion>();
    gtirb::AuxDataContainer::registerAuxDataType<PeSectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<PeImportedSymbols>();
    gtirb::AuxDataContainer::registerAuxDataType<PeExportedSymbols>();
    gtirb::AuxDataContainer::registerAuxDataType<ExportEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<ImportEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<PeResources>();
    gtirb::AuxDataContainer::registerAuxDataType<SouffleFacts>();
    gtirb::AuxDataContainer::registerAuxDataType<SouffleOutputs>();
    gtirb::AuxDataContainer::registerAuxDataType<RawEntries>();
}

void registerDatalogLoaders()
{
#if defined(DDISASM_ARM_64)
    // Register ELF-ARM64-LE target.
    DatalogProgram::registerLoader(
        {gtirb::FileFormat::ELF, gtirb::ISA::ARM64, gtirb::ByteOrder::Little}, ElfArm64Loader);
#endif

#if defined(DDISASM_X86_32)
    // Register ELF-X86-LE target.
    DatalogProgram::registerLoader(
        {gtirb::FileFormat::ELF, gtirb::ISA::IA32, gtirb::ByteOrder::Little}, ElfX86Loader);

    // Register PE-X86-LE target.
    DatalogProgram::registerLoader(
        {gtirb::FileFormat::PE, gtirb::ISA::IA32, gtirb::ByteOrder::Little}, PeX86Loader);
#endif

#if defined(DDISASM_X86_64)
    // Register ELF-X64-LE target.
    DatalogProgram::registerLoader(
        {gtirb::FileFormat::ELF, gtirb::ISA::X64, gtirb::ByteOrder::Little}, ElfX64Loader);

    // Register PE-X64-LE target.
    DatalogProgram::registerLoader(
        {gtirb::FileFormat::PE, gtirb::ISA::X64, gtirb::ByteOrder::Little}, PeX64Loader);
#endif
}
