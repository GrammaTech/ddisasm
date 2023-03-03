//===- ElfLoader.cpp --------------------------------------------*- C++ -*-===//
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
//  GNU Affero General Public
//  License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "ElfLoader.h"

#include "../../AuxDataSchema.h"
#include "../../Endian.h"
#include "../Relations.h"

void ElfDynamicEntryLoader(const gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    std::vector<relations::DynamicEntry> DynamicEntries;

    // Load Dynamic entries from aux data.
    if(auto *Table = Module.getAuxData<gtirb::schema::DynamicEntries>())
    {
        for(auto [Name, Value] : *Table)
        {
            DynamicEntries.push_back({Name, Value});
        }
    }

    relations::insert(Program, "dynamic_entry", std::move(DynamicEntries));
}

void ElfSymbolLoader(const gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    std::vector<relations::Symbol> Symbols;

    // Find extra ELF symbol information in aux data.
    auto *SymbolInfo = Module.getAuxData<gtirb::schema::ElfSymbolInfo>();
    auto *SymbolTabIdxInfo = Module.getAuxData<gtirb::schema::ElfSymbolTabIdxInfo>();

    // Load symbols with extra symbol information, if available.
    for(auto &Symbol : Module.symbols())
    {
        std::string Name = Symbol.getName();
        gtirb::Addr Addr = Symbol.getAddress().value_or(gtirb::Addr(0));

        auxdata::ElfSymbolInfo Info = {0, "NOTYPE", "GLOBAL", "DEFAULT", 0};
        if(SymbolInfo)
        {
            auto Found = SymbolInfo->find(Symbol.getUUID());

            // FIXME: Error handling
            if(Found == SymbolInfo->end())
            {
                throw std::logic_error("Symbol " + Symbol.getName()
                                       + " missing from elfSymbolInfo AuxData table");
            }

            Info = Found->second;
        }

        auxdata::ElfSymbolTabIdxInfo TableIndexes =
            std::vector<std::tuple<std::string, uint64_t>>();
        if(SymbolTabIdxInfo)
        {
            auto Found = SymbolTabIdxInfo->find(Symbol.getUUID());

            // FIXME: Error handling
            if(Found == SymbolTabIdxInfo->end())
            {
                throw std::logic_error("Symbol " + Symbol.getName()
                                       + " missing from elfSymbolTabIdxInfo AuxData table");
            }
            TableIndexes = Found->second;
        }

        auto [Size, Type, Binding, Visibility, SectionIndex] = Info;
        if(TableIndexes.size() > 0)
        {
            for(auto &IndexPair : TableIndexes)
            {
                const auto &[OriginTable, TableIndex] = IndexPair;
                Symbols.push_back({Addr, Size, Type, Binding, Visibility, SectionIndex, OriginTable,
                                   TableIndex, Name});
            }
        }
        else
        {
            Symbols.push_back(
                {Addr, Size, Type, Binding, Visibility, SectionIndex, "NONE", 0, Name});
        }
    }

    relations::insert(Program, "symbol", std::move(Symbols));

    if(auto *Relocations = Module.getAuxData<gtirb::schema::Relocations>())
    {
        relations::insert(Program, "relocation", *Relocations);
    }
}

void ElfExceptionLoader(const gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    ElfExceptionDecoder Decoder(Module);
    Decoder.addExceptionInformation(Program);
}

ElfExceptionDecoder::ElfExceptionDecoder(const gtirb::Module &module)
{
    uint8_t ptrsize;
    switch(module.getISA())
    {
        case gtirb::ISA::ARM:
        case gtirb::ISA::IA32:
        case gtirb::ISA::MIPS32:
        {
            ptrsize = 4;
            break;
        }
        default:
        {
            ptrsize = 8;
            break;
        }
    }

    std::string ehFrame, ehFrameHeader, gccExcept;
    uint64_t addressEhFrame(0), addressEhFrameHeader(0), addressGccExcept(0);

    auto ehFrameSections = module.findSections(".eh_frame");
    for(auto &ehFrameSection : ehFrameSections)
    {
        assert(ehFrameSection.getAddress() && "Found .eh_frame section without an address.");
        addressEhFrame = static_cast<uint64_t>(*ehFrameSection.getAddress());
        if(auto it = ehFrameSection.findByteIntervalsAt(*ehFrameSection.getAddress()); !it.empty())
        {
            const gtirb::ByteInterval &interval = *it.begin();
            assert(ehFrameSection.getSize() == interval.getSize()
                   && "Expected single .eh_frame byte interval.");

            const char *bytes = interval.rawBytes<const char>();
            const char *end = bytes + interval.getInitializedSize();
            ehFrame.assign(bytes, end);
        }
    }
    auto ehFrameHeaderSections = module.findSections(".eh_frame_hdr");
    for(auto &ehFrameHeaderSection : ehFrameHeaderSections)
    {
        assert(ehFrameHeaderSection.getAddress()
               && "Found .eh_frame_hdr section without an address.");
        addressEhFrameHeader = static_cast<uint64_t>(*ehFrameHeaderSection.getAddress());
        if(auto it = ehFrameHeaderSection.findByteIntervalsAt(*ehFrameHeaderSection.getAddress());
           !it.empty())
        {
            const gtirb::ByteInterval &interval = *it.begin();
            assert(ehFrameHeaderSection.getSize() == interval.getSize()
                   && "Expected single .eh_frame_hdr byte interval.");

            const char *bytes = interval.rawBytes<const char>();
            const char *end = bytes + interval.getInitializedSize();
            ehFrameHeader.assign(bytes, end);
        }
    }
    auto gccExceptSections = module.findSections(".gcc_except_table");
    for(auto &gccExceptSection : gccExceptSections)
    {
        assert(gccExceptSection.getAddress()
               && "Found .gcc_except_table section without an address.");
        addressGccExcept = static_cast<uint64_t>(*gccExceptSection.getAddress());
        if(auto it = gccExceptSection.findByteIntervalsAt(*gccExceptSection.getAddress());
           !it.empty())
        {
            const gtirb::ByteInterval &interval = *it.begin();
            assert(gccExceptSection.getSize() == interval.getSize()
                   && "Expected single .gcc_except_table byte interval.");

            const char *bytes = interval.rawBytes<char>();
            const char *end = bytes + interval.getInitializedSize();
            gccExcept.assign(bytes, end);
        }
    }
    ehParser = EHP::EHFrameParser_t::factory(ptrsize, EHP::EHPEndianness_t::HOST, ehFrame,
                                             addressEhFrame, ehFrameHeader, addressEhFrameHeader,
                                             gccExcept, addressGccExcept);
}

void ElfExceptionDecoder::addExceptionInformation(souffle::SouffleProgram &Program)
{
    auto *cieRelation = Program.getRelation("cie_entry");
    auto *cieEncodingRelation = Program.getRelation("cie_encoding");
    auto *ciePersonalityRelation = Program.getRelation("cie_personality");
    for(const EHP::CIEContents_t *cie : *(ehParser->getCIEs()))
    {
        cieRelation->insert(getCIEEntry(cieRelation, cie));
        cieEncodingRelation->insert(getCIEEncoding(cieEncodingRelation, cie));
        ciePersonalityRelation->insert(getCIEPersonality(ciePersonalityRelation, cie));
    }

    auto *fdeRelation = Program.getRelation("fde_entry");
    auto *fdePtrLocationsRelation = Program.getRelation("fde_pointer_locations");
    auto *fdeInsnRelation = Program.getRelation("fde_instruction");
    auto *lsdaRelation = Program.getRelation("lsda");
    auto *lsdaPtrLocationsRelation = Program.getRelation("lsda_pointer_locations");
    auto *callSiteRelation = Program.getRelation("lsda_callsite");
    auto *typeEntryRelation = Program.getRelation("lsda_type_entry");

    for(const EHP::FDEContents_t *fde : *(ehParser->getFDEs()))
    {
        fdeRelation->insert(getFDE(fdeRelation, fde));
        fdePtrLocationsRelation->insert(getFDEPointerLocations(fdePtrLocationsRelation, fde));

        // First iterate over instructions in the CIE in reverse order
        // to obtain their addresses from the end of the CIE.
        const EHP::EHProgramInstructionVector_t *CieInstructions =
            fde->getCIE().getProgram().getInstructions();
        uint64_t InsnAddr = fde->getCIE().getPosition() + fde->getCIE().getLength();
        uint64_t InsnIndex = CieInstructions->size();
        for(auto it = CieInstructions->rbegin(); it != CieInstructions->rend(); ++it)
        {
            InsnIndex--;
            InsnAddr -= (*it)->getSize();
            fdeInsnRelation->insert(
                getEHProgramInstruction(fdeInsnRelation, InsnIndex, InsnAddr, *it, fde));
        }
        // Then interate over instructions in the FDE in regular order.
        InsnIndex = CieInstructions->size();
        InsnAddr = fde->getLSDAAddressPosition() + fde->getLSDAAddressSize();
        for(const EHP::EHProgramInstruction_t *insn : *(fde->getProgram().getInstructions()))
        {
            fdeInsnRelation->insert(
                getEHProgramInstruction(fdeInsnRelation, InsnIndex, InsnAddr, insn, fde));
            InsnAddr += insn->getSize();
            ++InsnIndex;
        }

        auto *lsda = fde->getLSDA();
        if(lsda && fde->getLSDAAddress() != 0)
        {
            lsdaRelation->insert(getLSDA(lsdaRelation, lsda, fde));
            lsdaPtrLocationsRelation->insert(
                getLSDAPointerLocations(lsdaPtrLocationsRelation, lsda, fde));
            for(const EHP::LSDACallSite_t *callSite : *(lsda->getCallSites()))
            {
                callSiteRelation->insert(getLSDACallSite(callSiteRelation, callSite, lsda));
            }
            uint64_t index = 0;
            for(const EHP::LSDATypeTableEntry_t *typeEntry : *(lsda->getTypeTable()))
            {
                typeEntryRelation->insert(
                    getLSDATypetableEntry(typeEntryRelation, index, typeEntry, lsda));
                ++index;
            }
        }
    }
}

souffle::tuple ElfExceptionDecoder::getCIEEntry(souffle::Relation *relation,
                                                const EHP::CIEContents_t *cie)
{
    souffle::tuple tuple(relation);
    tuple << cie->getPosition() << cie->getLength() << cie->getCAF() << cie->getDAF();
    return tuple;
}

souffle::tuple ElfExceptionDecoder::getCIEEncoding(souffle::Relation *relation,
                                                   const EHP::CIEContents_t *cie)
{
    souffle::tuple tuple(relation);
    uint64_t fdeEnconding = cie->getFDEEncoding();
    uint64_t lsdaEncoding = cie->getLSDAEncoding();
    tuple << cie->getPosition() << fdeEnconding << lsdaEncoding;
    return tuple;
}

souffle::tuple ElfExceptionDecoder::getCIEPersonality(souffle::Relation *relation,
                                                      const EHP::CIEContents_t *cie)
{
    souffle::tuple tuple(relation);
    tuple << cie->getPosition() << cie->getPersonality() << cie->getPersonalityPointerPosition()
          << cie->getPersonalityPointerSize()
          << static_cast<uint64_t>(cie->getPersonalityEncoding());
    return tuple;
}

souffle::tuple ElfExceptionDecoder::getFDE(souffle::Relation *relation,
                                           const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getPosition() << fde->getLength() << fde->getCIE().getPosition()
          << fde->getStartAddress() << fde->getEndAddress() << fde->getLSDAAddress();
    return tuple;
}

souffle::tuple ElfExceptionDecoder::getFDEPointerLocations(souffle::Relation *relation,
                                                           const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getPosition() << fde->getStartAddressPosition() << fde->getEndAddressPosition()
          << fde->getEndAddressSize() << fde->getLSDAAddressPosition() << fde->getLSDAAddressSize();
    return tuple;
}

souffle::tuple ElfExceptionDecoder::getEHProgramInstruction(souffle::Relation *relation,
                                                            uint64_t index, uint64_t insnAddr,
                                                            const EHP::EHProgramInstruction_t *insn,
                                                            const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getPosition() << index << insn->getSize() << insnAddr;
    auto insnTuple = insn->decode();
    tuple << std::get<0>(insnTuple) << std::get<1>(insnTuple) << std::get<2>(insnTuple);
    return tuple;
}

souffle::tuple ElfExceptionDecoder::getLSDA(souffle::Relation *relation, const EHP::LSDA_t *lsda,
                                            const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getLSDAAddress() << lsda->getCallSiteTableAddress()
          << static_cast<uint64_t>(lsda->getCallSiteTableEncoding())
          << lsda->getCallSiteTableLength() << lsda->getTypeTableAddress()
          << static_cast<uint64_t>(lsda->getTypeTableEncoding())
          << lsda->getLandingPadBaseAddress();
    return tuple;
}

souffle::tuple ElfExceptionDecoder::getLSDAPointerLocations(souffle::Relation *relation,
                                                            const EHP::LSDA_t *lsda,
                                                            const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getLSDAAddress() << lsda->getTypeTableAddressLocation()
          << lsda->getCallSiteTableAddressLocation();
    return tuple;
}

souffle::tuple ElfExceptionDecoder::getLSDACallSite(souffle::Relation *relation,
                                                    const EHP::LSDACallSite_t *callSite,
                                                    const EHP::LSDA_t *lsda)
{
    souffle::tuple tuple(relation);
    tuple << lsda->getCallSiteTableAddress() << callSite->getCallSiteAddressPosition()
          << callSite->getCallSiteAddress() << callSite->getCallSiteEndAddressPosition()
          << callSite->getCallSiteEndAddress() << callSite->getLandingPadAddressPosition()
          << callSite->getLandingPadAddress() << callSite->getLandingPadAddressEndPosition();
    return tuple;
}

souffle::tuple ElfExceptionDecoder::getLSDATypetableEntry(
    souffle::Relation *relation, uint64_t index, const EHP::LSDATypeTableEntry_t *typeEntry,
    const EHP::LSDA_t *lsda)
{
    souffle::tuple tuple(relation);
    tuple << lsda->getTypeTableAddress() << index << typeEntry->getTypeInfoPointer();
    return tuple;
}

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

void ElfArchInfoLoader(const gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    std::vector<relations::ArchInfo> ArchInfo;

    // Load arch info from aux data.
    if(auto *Table = Module.getAuxData<gtirb::schema::ArchInfo>())
    {
        for(auto [Key, Value] : *Table)
        {
            ArchInfo.push_back({Key, Value});
        }
    }

    relations::insert(Program, "arch_info", std::move(ArchInfo));
}

/**
Locate function starts from ARM exception tables.

The format is defined by the ARM Exception-Handling ABI (EHABI):
https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst

If we fail to parse in any way, we clear the arm_exidx_entry and allow ddisasm
to proceed without it.
*/
void ArmUnwindLoader(const gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    auto *FunctionStartRelation = Program.getRelation("arm_exidx_entry");

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

        uint64_t CantUnwind = static_cast<uint64_t>(EntryData == 1);

        souffle::tuple tuple(FunctionStartRelation);
        tuple << gtirb::Addr(FnStart);
        tuple << CantUnwind;
        FunctionStartRelation->insert(tuple);

        // TODO: in entries where Data is an offset referencing the .ARM.extab
        // section, the referenced table entry may contain "decriptors"; these
        // may reference landing pads used by exception handling, which could
        // be useful metadata for ddisasm. I have not yet observed a binary
        // with any, however.
    }
}
