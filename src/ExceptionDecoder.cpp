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
    t << fde->getPosition() << fde->getStartAddress() << fde->getEndAddress()
      << fde->getLSDAAddress() << fde->getCIE().getPersonality()
      << fde->getCIE().getPersonalityPointerPosition();
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

void ExceptionDecoder::addExceptionInformation(souffle::SouffleProgram *prog)
{
    auto *fdeRelation = prog->getRelation("fde_entry");
    auto *lsdaRelation = prog->getRelation("lsda");
    auto *callSiteRelation = prog->getRelation("lsda_callsite");
    auto *typeEntryRelation = prog->getRelation("lsda_type_entry");
    for(const EHP::FDEContents_t *fde : *(ehParser->getFDEs()))
    {
        souffle::tuple fdeTuple(fdeRelation);
        fdeTuple << fde;
        fdeRelation->insert(fdeTuple);
        auto *lsda = fde->getLSDA();
        if(lsda)
        {
            souffle::tuple lsdaTuple(lsdaRelation);
            lsdaTuple << fde->getLSDAAddress();
            lsdaTuple << lsda;
            lsdaRelation->insert(lsdaTuple);

            uint64_t index = 0;
            for(const EHP::LSDACallSite_t *callSite : *(lsda->getCallSites()))
            {
                souffle::tuple callSiteTuple(callSiteRelation);
                callSiteTuple << lsda->getCallSiteTableAddress();
                callSiteTuple << callSite;
                callSiteRelation->insert(callSiteTuple);
                ++index;
            }
            index = 0;
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