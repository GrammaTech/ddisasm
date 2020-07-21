#include <gtest/gtest.h>

#include <LIEF/LIEF.hpp>
#include <gtirb/gtirb.hpp>

#include "../gtirb-builder/ElfReader.h"
#include "../gtirb-builder/GtirbBuilder.h"

using GTIRB = GtirbBuilder::GTIRB;

class ElfReaderTest : public ::testing::TestWithParam<const char*>
{
protected:
    void SetUp() override
    {
        const std::string& Path(GetParam());
        ELF = LIEF::ELF::Parser::parse(Path);
    }
    std::shared_ptr<LIEF::ELF::Binary> ELF;
};

TEST_P(ElfReaderTest, read)
{
    {
        gtirb::ErrorOr<GTIRB> GTIRB = GtirbBuilder::read("/file/does/not/exist");
        EXPECT_EQ(GTIRB, GtirbBuilder::build_error::FileNotFound);
        EXPECT_FALSE(GTIRB);
    }
    {
        gtirb::ErrorOr<GTIRB> GTIRB = GtirbBuilder::read("ElfReader.Test.cpp");
        EXPECT_EQ(GTIRB, GtirbBuilder::build_error::ParseError);
        EXPECT_FALSE(GTIRB);
    }
    {
        gtirb::ErrorOr<GTIRB> GTIRB = GtirbBuilder::read(GetParam());
        EXPECT_TRUE(GTIRB);
    }
}

TEST_P(ElfReaderTest, entrypoint)
{
    gtirb::ErrorOr<GTIRB> GTIRB = GtirbBuilder::read(GetParam());
    gtirb::Module& Module = *(GTIRB->IR->modules().begin());
    const gtirb::CodeBlock* EntryPoint = Module.getEntryPoint();
    EXPECT_EQ(EntryPoint->getAddress().value(), gtirb::Addr(ELF->entrypoint()));
}

TEST_P(ElfReaderTest, sections)
{
    std::unordered_set<std::string> Names;
    std::unordered_map<std::string, size_t> Sizes;
    std::unordered_map<std::string, uint64_t> Addresses;

    for(const auto& Section : ELF->sections())
    {
        if(Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC))
        {
            Names.insert(Section.name());
            Sizes[Section.name()] = Section.size();
            Addresses[Section.name()] = Section.virtual_address();
        }
    }

    gtirb::ErrorOr<GTIRB> GTIRB = GtirbBuilder::read(GetParam());
    gtirb::Module& Module = *(GTIRB->IR->modules().begin());
    for(const auto& Section : Module.sections())
    {
        const std::string& Name = Section.getName();
        EXPECT_EQ(Names.count(Name), 1);
        EXPECT_EQ(Sizes[Name], Section.getSize());
        EXPECT_EQ(Addresses[Name], static_cast<uint64_t>(Section.getAddress().value()));
    }
}

TEST_P(ElfReaderTest, libraries)
{
    std::unordered_set<std::string> Libraries;
    for(const auto& DynamicEntry : ELF->dynamic_entries())
    {
        if(const auto DynamicEntryLibrary =
               dynamic_cast<const LIEF::ELF::DynamicEntryLibrary*>(&DynamicEntry))
        {
            if(DynamicEntryLibrary->tag() == LIEF::ELF::DYNAMIC_TAGS::DT_NEEDED)
            {
                Libraries.insert(DynamicEntryLibrary->name());
            }
        }
    }

    gtirb::ErrorOr<GTIRB> GTIRB = GtirbBuilder::read(GetParam());
    gtirb::Module& Module = *(GTIRB->IR->modules().begin());

    auto* AuxData = Module.getAuxData<gtirb::schema::Libraries>();
    EXPECT_NE(AuxData, nullptr);
    std::unordered_set<std::string> ModuleLibraries(AuxData->begin(), AuxData->end());
    EXPECT_EQ(Libraries, ModuleLibraries);
}

TEST_P(ElfReaderTest, libraryPaths)
{
    gtirb::ErrorOr<GTIRB> GTIRB = GtirbBuilder::read("inputs/man");
    gtirb::Module& Module = *(GTIRB->IR->modules().begin());

    auto* AuxData = Module.getAuxData<gtirb::schema::LibraryPaths>();
    EXPECT_NE(AuxData, nullptr);

    std::vector<std::string> LibraryPaths = {"/usr/lib/man-db"};
    EXPECT_EQ(*AuxData, LibraryPaths);
}

INSTANTIATE_TEST_SUITE_P(GtirbBuilderTests, ElfReaderTest, testing::Values("inputs/hello.x64.elf"));
