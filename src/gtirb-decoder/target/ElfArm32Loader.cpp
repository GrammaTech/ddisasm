//===- ElfArm32Loader.cpp ---------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019-2022 GrammaTech, Inc.
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
#include "ElfArm32Loader.h"

#include "../../Endian.h"

struct ExidxEntry
{
    uint32_t FnPrel;
    uint32_t Data;
};

static uint32_t decodePrel31(uint32_t PRel31, uint32_t From)
{
    int32_t Offset = PRel31 & 0x7FFFFFFF;

    // sign-extend prel31 to 32 bits
    if(Offset & 0x40000000)
    {
        Offset |= static_cast<int32_t>(0x80000000);
    }

    return From + Offset;
}

static const gtirb::Section *getSection(const gtirb::Module &Module, const std::string &Name)
{
    auto Sections = Module.findSections(Name);

    if(Sections.empty())
    {
        return nullptr;
    }

    if(Sections.front() != Sections.back())
    {
        std::cerr << "WARNING: Multiple " << Name << " sections\n";
        return nullptr;
    }

    return &Sections.front();
}

static const uint8_t *getSectionBytes(const gtirb::Section &Section)
{
    if(auto It = Section.findByteIntervalsAt(*Section.getAddress()); !It.empty())
    {
        const gtirb::ByteInterval &Interval = *It.begin();
        if(Section.getSize() != Interval.getSize())
        {
            std::cerr << "WARNING: Expected single " << Section.getName() << " byte interval\n";
            return nullptr;
        }
        return Interval.rawBytes<uint8_t>();
    }
    else
    {
        std::cerr << "WARNING: No byte interval for " << Section.getName() << " section\n";
        return nullptr;
    }
}

/**
Locate function starts from ARM exception tables.

The format is defined by the ARM Exception-Handling ABI (EHABI):
https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst

If we fail to parse in any way, we clear the arm_exidx_entry and allow ddisasm
to proceed without it.
*/
void ArmUnwindLoader(const gtirb::Module &Module, DatalogProgram &Program)
{
    auto *FunctionStartRelation = Program.get()->getRelation("arm_exidx_entry");

    auto ExidxSection = getSection(Module, ".ARM.exidx");
    if(ExidxSection == nullptr)
    {
        return;
    }

    auto ExidxBytes = getSectionBytes(*ExidxSection);
    if(ExidxBytes == nullptr)
    {
        return;
    }

    uint32_t ExidxSectionAddr =
        static_cast<uint32_t>(static_cast<uint64_t>(*(ExidxSection->getAddress())));
    size_t ExidxEntryCount = *(ExidxSection->getSize()) / sizeof(ExidxEntry);

    for(size_t I = 0; I < ExidxEntryCount; I++)
    {
        const uint8_t *EntryBytes = ExidxBytes + I * sizeof(ExidxEntry);
        const ExidxEntry *Entry = reinterpret_cast<const ExidxEntry *>(EntryBytes);
        uint32_t FnPrel = le32toh(Entry->FnPrel);
        uint32_t EntryData = le32toh(Entry->Data);
        if(FnPrel & 0x80000000)
        {
            std::cerr << "WARNING: Failed to parse .ARM.exidx section";
            FunctionStartRelation->purge();
            return;
        }

        // Get offset to function start
        uint32_t ExidxEntryAddr = ExidxSectionAddr + I * sizeof(ExidxEntry);
        uint32_t FnStart = decodePrel31(FnPrel, ExidxEntryAddr);

        souffle::tuple tuple(FunctionStartRelation);
        tuple << gtirb::Addr(FnStart);
        FunctionStartRelation->insert(tuple);

        // TODO: in entries where Data is an offset referencing the .ARM.extab
        // section, the referenced table entry may contain "decriptors"; these
        // may reference landing pads used by exception handling, which could
        // be useful metadata for ddisasm. I have not yet observed a binary
        // with any, however.
    }
}

CompositeLoader ElfArm32Loader()
{
    CompositeLoader Loader("souffle_disasm_arm32");
    Loader.add(ModuleLoader);
    Loader.add(SectionLoader);
    Loader.add<Arm32Loader>();
    Loader.add<DataLoader>(DataLoader::Pointer::DWORD);
    Loader.add(ElfDynamicEntryLoader);
    Loader.add(ElfSymbolLoader);
    Loader.add(ElfExceptionLoader);
    Loader.add(ArmUnwindLoader);
    return Loader;
}
