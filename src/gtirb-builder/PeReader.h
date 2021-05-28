//===- PeReader.h       -----------------------------------------*- C++ -*-===//
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
#ifndef PE_GTIRB_BUILDER_H_
#define PE_GTIRB_BUILDER_H_

#include "./GtirbBuilder.h"

class PeReader : public GtirbBuilder
{
public:
    PeReader(std::string Path, std::shared_ptr<LIEF::Binary> Binary);

    gtirb::ErrorOr<GTIRB> build() override;

protected:
    std::shared_ptr<LIEF::PE::Binary> Pe;

    void initModule() override;
    void buildSections() override;
    void buildSymbols() override;
    void addEntryBlock() override;
    void addAuxData() override;

    std::vector<PeResource> resources();
    std::vector<ImportEntry> importEntries();
    std::vector<ExportEntry> exportEntries();
};

#endif // PE_GTIRB_BUILDER_H_
