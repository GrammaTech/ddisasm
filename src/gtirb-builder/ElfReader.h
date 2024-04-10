//===- ElfReader.h ----------------------------------------------*- C++ -*-===//
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
#ifndef ELF_GTIRB_BUILDER_H_
#define ELF_GTIRB_BUILDER_H_

#include "./GtirbBuilder.h"

class ElfReaderException : public std::exception
{
    std::string error_message;

public:
    ElfReaderException(const std::string& msg) : error_message(msg)
    {
    }

    virtual const char* what() const throw()
    {
        return error_message.c_str();
    }
};

class ElfReader : public GtirbBuilder
{
public:
    ElfReader(std::string Path, std::string Name, std::shared_ptr<gtirb::Context> Context,
              gtirb::IR* IR, std::shared_ptr<LIEF::Binary> Binary);

protected:
    std::shared_ptr<LIEF::ELF::Binary> Elf;

    void buildSections() override;
    void buildSymbols() override;
    void addEntryBlock() override;
    void addAuxData() override;

    void relocateSections();
    uint64_t tlsBaseAddress();

    std::string getRelocationType(const LIEF::ELF::Relocation& Entry);

private:
    uint64_t TlsBaseAddress = 0;

    std::optional<std::string> getStringAt(uint32_t Index);
    LIEF::span<const uint8_t> getStrTabBytes();

    // For sectionless binaries
    std::map<std::string, uint64_t> getDynamicEntries();
    std::string inferDynMode();
    std::optional<std::pair<uint64_t, uint64_t>> getTls();
    void resurrectSections();
    void resurrectSymbols();
    void createGPforMIPS(uint64_t SecIndex,
                         std::map<gtirb::UUID, auxdata::ElfSymbolInfo>& SymbolInfo,
                         std::map<gtirb::UUID, auxdata::ElfSymbolTabIdxInfo>& SymbolTabIdxInfo);

    const LIEF::ELF::Section* findRelocationSection(const LIEF::ELF::Relocation& Relocation);

    // Map version strings (e.g., GLIBC_2.2.5) to SymbolVersionIds
    // Usually there's only one VersionId for each version string, but it
    // would be possible for there to be more.
    std::map<std::string, std::set<gtirb::provisional_schema::SymbolVersionId>> VersionToIds;

    // <Value, Size, Type, Binding, Scope, SectionIndex, Name>
    using SymbolKey = std::tuple<uint64_t, uint64_t, std::string, std::string, std::string,
                                 uint64_t, std::string>;
    using TableDecl = std::tuple<std::string, uint64_t>;
    std::map<SymbolKey,
             std::map<gtirb::provisional_schema::SymbolVersionId, std::vector<TableDecl>>>
        Symbols;

    // Map SymbolKey to Gtirb Symbol
    std::map<SymbolKey, gtirb::Symbol*> LiefToGtirbSymbols;

    // Helper functions to process LIEF Symbols with Versions
    uint64_t getSymbolValue(const LIEF::ELF::Symbol& Symbol);
    std::pair<std::string, std::string> getNameAndVersionStr(const LIEF::ELF::Symbol& Symbol);
    SymbolKey getSymbolKey(const LIEF::ELF::Symbol& Symbol, const std::string& Name);
    void updateVersionMap(const LIEF::ELF::Symbol& Symbol, const std::string& TableName,
                          uint64_t TableIndex);

    std::string getVersionedName(const SymbolKey& Key);

    // TODO: Handle duplicate section names?
    std::map<std::string, uint64_t> SectionRelocations;

    // Unloaded, literal section whitelist.
    const std::unordered_set<std::string> Literals = {"pydata", ".ARM.attributes"};
};

#endif // ELF_GTIRB_BUILDER_H_
