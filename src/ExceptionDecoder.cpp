//===- ExceptionDecoder.cpp ------------------------------------------*- C++ -*-===//
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

#include "ExceptionDecoder.h"

souffle::tuple &operator<<(souffle::tuple &t, const EHP::FDEContents_t *fde)
{
    t << fde->getPosition() << fde->getLength() << fde->getCIE().getPosition()
      << fde->getStartAddress() << fde->getEndAddress() << fde->getLSDAAddress();
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const EHP::LSDACallSite_t *callSite)
{
    t << callSite->getCallSiteAddressPosition() << callSite->getCallSiteAddress()
      << callSite->getCallSiteEndAddressPosition() << callSite->getCallSiteEndAddress()
      << callSite->getLandingPadAddressPosition() << callSite->getLandingPadAddress()
      << callSite->getLandingPadAddressEndPosition();
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const EHP::LSDA_t *lsda)
{
    t << lsda->getCallSiteTableAddress() << lsda->getCallSiteTableEncoding()
      << lsda->getTypeTableAddress() << lsda->getTypeTableEncoding()
      << lsda->getLandingPadBaseAddress();
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const std::tuple<std::string, int64_t, int64_t> &x)
{
    t << std::get<0>(x) << std::get<1>(x) << std::get<2>(x);
    return t;
}

ExceptionDecoder::ExceptionDecoder(Elf_reader &elf)
{
    uint8_t ptrsize(8);
    uint64_t size;
    uint64_t addressEhFrame, addressEhFrameHeader, addressGccExcept;
    char *buff = elf.get_section(".eh_frame", size, addressEhFrame);
    std::string ehFrame(buff, size);
    buff = elf.get_section(".eh_frame_hdr", size, addressEhFrameHeader);
    std::string ehFrameHeader(buff, size);
    buff = elf.get_section(".gcc_except_table", size, addressGccExcept);
    std::string gccExcept(buff, size);
    ehParser = EHP::EHFrameParser_t::factory(ptrsize, ehFrame, addressEhFrame, ehFrameHeader,
                                             addressEhFrameHeader, gccExcept, addressGccExcept);
    ehParser->print();
}

souffle::tuple ExceptionDecoder::getCIEEntry(souffle::Relation *relation,
                                             const EHP::CIEContents_t *cie)
{
    souffle::tuple tuple(relation);
    tuple << cie->getPosition() << cie->getLength() << cie->getCAF() << cie->getDAF();
    return tuple;
}
souffle::tuple ExceptionDecoder::getCIEEncoding(souffle::Relation *relation,
                                                const EHP::CIEContents_t *cie)
{
    souffle::tuple tuple(relation);
    uint64_t fdeEnconding = cie->getFDEEncoding();
    uint64_t lsdaEncoding = cie->getLSDAEncoding();
    tuple << cie->getPosition() << fdeEnconding << lsdaEncoding;
    return tuple;
}
souffle::tuple ExceptionDecoder::getCIEPersonality(souffle::Relation *relation,
                                                   const EHP::CIEContents_t *cie)
{
    souffle::tuple tuple(relation);
    tuple << cie->getPosition() << cie->getPersonality() << cie->getPersonalityPointerPosition()
          << cie->getPersonalityPointerSize() << cie->getPersonalityEncoding();
    return tuple;
}

souffle::tuple ExceptionDecoder::getFDEPointerLocations(souffle::Relation *relation,
                                                        const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getPosition() << fde->getStartAddressPosition() << fde->getEndAddressPosition()
          << fde->getEndAddressSize() << fde->getLSDAAddressPosition() << fde->getLSDAAddressSize();
    return tuple;
}
void ExceptionDecoder::addExceptionInformation(souffle::SouffleProgram *prog)
{
    auto *cieRelation = prog->getRelation("cie_entry");
    auto *cieEncodingRelation = prog->getRelation("cie_encoding");
    auto *ciePersonalityRelation = prog->getRelation("cie_personality");
    for(const EHP::CIEContents_t *cie : *(ehParser->getCIEs()))
    {
        cieRelation->insert(getCIEEntry(cieRelation, cie));
        cieEncodingRelation->insert(getCIEEncoding(cieEncodingRelation, cie));
        ciePersonalityRelation->insert(getCIEPersonality(ciePersonalityRelation, cie));
    }

    auto *fdeRelation = prog->getRelation("fde_entry");
    auto *fdePointerLocationsRelation = prog->getRelation("fde_pointer_locations");
    auto *fdeInsnRelation = prog->getRelation("fde_instruction");
    auto *lsdaRelation = prog->getRelation("lsda");
    auto *callSiteRelation = prog->getRelation("lsda_callsite");
    auto *typeEntryRelation = prog->getRelation("lsda_type_entry");

    for(const EHP::FDEContents_t *fde : *(ehParser->getFDEs()))
    {
        souffle::tuple fdeTuple(fdeRelation);
        fdeTuple << fde;
        fdeRelation->insert(fdeTuple);
        fdePointerLocationsRelation->insert(
            getFDEPointerLocations(fdePointerLocationsRelation, fde));
        uint64_t insnIndex = 0;
        for(const EHP::EHProgramInstruction_t *insn : *(fde->getProgram().getInstructions()))
        {
            auto insnTuple = insn->decode();
            souffle::tuple insnSouffleTuple(fdeInsnRelation);
            insnSouffleTuple << fde->getPosition();
            insnSouffleTuple << insnIndex;
            insnSouffleTuple << insn->getSize();
            insnSouffleTuple << insnTuple;
            ++insnIndex;
            fdeInsnRelation->insert(insnSouffleTuple);
        }

        auto *lsda = fde->getLSDA();
        if(lsda)
        {
            souffle::tuple lsdaTuple(lsdaRelation);
            lsdaTuple << fde->getLSDAAddress();
            lsdaTuple << lsda;
            lsdaRelation->insert(lsdaTuple);

            for(const EHP::LSDACallSite_t *callSite : *(lsda->getCallSites()))
            {
                souffle::tuple callSiteTuple(callSiteRelation);
                callSiteTuple << lsda->getCallSiteTableAddress();
                callSiteTuple << callSite;
                callSiteRelation->insert(callSiteTuple);
            }
            uint64_t index = 0;
            for(const EHP::LSDATypeTableEntry_t *typeEntry : *(lsda->getTypeTable()))
            {
                souffle::tuple typeEntryTuple(typeEntryRelation);
                typeEntryTuple << lsda->getTypeTableAddress();
                typeEntryTuple << index;
                typeEntryTuple << typeEntry->getTypeInfoPointer();
                typeEntryRelation->insert(typeEntryTuple);
                ++index;
            }
        }
    }
}