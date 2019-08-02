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

ExceptionDecoder::ExceptionDecoder(std::shared_ptr<BinaryReader> binary)
{
    uint8_t ptrsize(8);
    std::string ehFrame, ehFrameHeader, gccExcept;
    uint64_t addressEhFrame(0), addressEhFrameHeader(0), addressGccExcept(0);

    if(auto ehFrameTuple = binary->get_section_content_and_address(".eh_frame"))
    {
        std::vector<uint8_t> ehFrameContent = std::get<0>(*ehFrameTuple);
        addressEhFrame = std::get<1>(*ehFrameTuple);
        ehFrame.assign(ehFrameContent.begin(), ehFrameContent.end());
    }
    if(auto ehFrameHeaderTuple = binary->get_section_content_and_address(".eh_frame_hdr"))
    {
        std::vector<uint8_t> ehFrameHeaderContent = std::get<0>(*ehFrameHeaderTuple);
        addressEhFrameHeader = std::get<1>(*ehFrameHeaderTuple);
        ehFrameHeader.assign(ehFrameHeaderContent.begin(), ehFrameHeaderContent.end());
    }
    if(auto gccExceptTuple = binary->get_section_content_and_address(".gcc_except_table"))
    {
        std::vector<uint8_t> gccExceptContent = std::get<0>(*gccExceptTuple);
        addressGccExcept = std::get<1>(*gccExceptTuple);
        gccExcept.assign(gccExceptContent.begin(), gccExceptContent.end());
    }
    ehParser = EHP::EHFrameParser_t::factory(ptrsize, ehFrame, addressEhFrame, ehFrameHeader,
                                             addressEhFrameHeader, gccExcept, addressGccExcept);
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
    auto *fdePtrLocationsRelation = prog->getRelation("fde_pointer_locations");
    auto *fdeInsnRelation = prog->getRelation("fde_instruction");
    auto *lsdaRelation = prog->getRelation("lsda");
    auto *lsdaPtrLocationsRelation = prog->getRelation("lsda_pointer_locations");
    auto *callSiteRelation = prog->getRelation("lsda_callsite");
    auto *typeEntryRelation = prog->getRelation("lsda_type_entry");

    for(const EHP::FDEContents_t *fde : *(ehParser->getFDEs()))
    {
        fdeRelation->insert(getFDE(fdeRelation, fde));
        fdePtrLocationsRelation->insert(getFDEPointerLocations(fdePtrLocationsRelation, fde));
        uint64_t insnIndex = 0;
        for(const EHP::EHProgramInstruction_t *insn :
            *(fde->getCIE().getProgram().getInstructions()))
        {
            fdeInsnRelation->insert(getEHProgramInstruction(fdeInsnRelation, insnIndex, insn, fde));
            ++insnIndex;
        }
        for(const EHP::EHProgramInstruction_t *insn : *(fde->getProgram().getInstructions()))
        {
            fdeInsnRelation->insert(getEHProgramInstruction(fdeInsnRelation, insnIndex, insn, fde));
            ++insnIndex;
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

souffle::tuple ExceptionDecoder::getFDE(souffle::Relation *relation, const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getPosition() << fde->getLength() << fde->getCIE().getPosition()
          << fde->getStartAddress() << fde->getEndAddress() << fde->getLSDAAddress();
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

souffle::tuple ExceptionDecoder::getEHProgramInstruction(souffle::Relation *relation,
                                                         uint64_t index,
                                                         const EHP::EHProgramInstruction_t *insn,
                                                         const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getPosition() << index << insn->getSize();
    auto insnTuple = insn->decode();
    tuple << std::get<0>(insnTuple) << std::get<1>(insnTuple) << std::get<2>(insnTuple);
    return tuple;
}

souffle::tuple ExceptionDecoder::getLSDA(souffle::Relation *relation, const EHP::LSDA_t *lsda,
                                         const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getLSDAAddress() << lsda->getCallSiteTableAddress()
          << lsda->getCallSiteTableEncoding() << lsda->getCallSiteTableLength()
          << lsda->getTypeTableAddress() << lsda->getTypeTableEncoding()
          << lsda->getLandingPadBaseAddress();
    return tuple;
}

souffle::tuple ExceptionDecoder::getLSDAPointerLocations(souffle::Relation *relation,
                                                         const EHP::LSDA_t *lsda,
                                                         const EHP::FDEContents_t *fde)
{
    souffle::tuple tuple(relation);
    tuple << fde->getLSDAAddress() << lsda->getTypeTableAddressLocation()
          << lsda->getCallSiteTableAddressLocation();
    return tuple;
}

souffle::tuple ExceptionDecoder::getLSDACallSite(souffle::Relation *relation,
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

souffle::tuple ExceptionDecoder::getLSDATypetableEntry(souffle::Relation *relation, uint64_t index,
                                                       const EHP::LSDATypeTableEntry_t *typeEntry,
                                                       const EHP::LSDA_t *lsda)
{
    souffle::tuple tuple(relation);
    tuple << lsda->getTypeTableAddress() << index << typeEntry->getTypeInfoPointer();
    return tuple;
}
