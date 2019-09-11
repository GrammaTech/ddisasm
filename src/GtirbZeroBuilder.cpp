//===- GtirbZeroBuilder.cpp ---------------------------------------------*- C++ -*-===//
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

#include "GtirbZeroBuilder.h"
#include <elf.h>
#include "BinaryReader.h"
#include "Elf_reader.h"

void buildSections(gtirb::Module &module, std::shared_ptr<BinaryReader> binary,
                   gtirb::Context &context)
{
    auto &byteMap = module.getImageByteMap();
    byteMap.setAddrMinMax(
        {gtirb::Addr(binary->get_min_address()), gtirb::Addr(binary->get_max_address())});
    std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> sectionProperties;
    for(auto &binSection : binary->get_sections())
    {
        if(binSection.flags & SHF_ALLOC)
        {
            gtirb::Section *section = gtirb::Section::Create(
                context, binSection.name, gtirb::Addr(binSection.address), binSection.size);
            module.addSection(section);
            sectionProperties[section->getUUID()] =
                std::make_tuple(binSection.type, binSection.flags);
            if(auto sectionData = binary->get_section_content_and_address(binSection.name))
            {
                std::vector<uint8_t> &sectionBytes = std::get<0>(*sectionData);
                std::byte *begin = reinterpret_cast<std::byte *>(sectionBytes.data());
                std::byte *end =
                    reinterpret_cast<std::byte *>(sectionBytes.data() + sectionBytes.size());
                byteMap.setData(gtirb::Addr(binSection.address),
                                boost::make_iterator_range(begin, end));
            }
        }
    }
    module.addAuxData("elfSectionProperties", std::move(sectionProperties));
}

void addAuxiliaryTables(gtirb::Module &module, std::shared_ptr<BinaryReader> binary)
{
    std::vector<std::string> binaryType = {binary->get_binary_type()};
    module.addAuxData("binary_type", binaryType);
    std::vector<uint64_t> entryPoint = {binary->get_entry_point()};
    module.addAuxData("entry_point", entryPoint);
    module.addAuxData("section_complete", binary->get_sections());
    module.addAuxData("symbol", binary->get_symbols());
    module.addAuxData("relocation", binary->get_relocations());
    module.addAuxData("libraries", binary->get_libraries());
    module.addAuxData("libraryPaths", binary->get_library_paths());
}

gtirb::IR *buildZeroIR(const std::string &filename, gtirb::Context &context)
{
    std::shared_ptr<BinaryReader> binary(new Elf_reader(filename));
    if(!binary->is_valid())
        return nullptr;
    auto ir = gtirb::IR::Create(context);
    gtirb::Module &module = *gtirb::Module::Create(context);
    module.setBinaryPath(filename);
    module.setFileFormat(binary->get_binary_format());
    module.setISAID(gtirb::ISAID::X64);
    ir->addModule(&module);
    buildSections(module, binary, context);
    addAuxiliaryTables(module, binary);

    return ir;
}