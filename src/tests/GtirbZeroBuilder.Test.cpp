#include <gtest/gtest.h>

#include <LIEF/LIEF.hpp>
#include <gtirb/gtirb.hpp>

#include "../GtirbZeroBuilder.h"

class GtirbZeroBuilderTest : public ::testing::TestWithParam<const char*>
{
};

TEST_P(GtirbZeroBuilderTest, buildSections)
{
    gtirb::Context Context;
    const std::string& Path(GetParam());
    gtirb::IR* IR = buildZeroIR(Path, Context);
    gtirb::Module& Module = *(IR->modules().begin());

    std::unique_ptr<LIEF::ELF::Binary> ELF = LIEF::ELF::Parser::parse(Path);
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

    for(const auto& Section : Module.sections())
    {
        const std::string& Name = Section.getName();
        EXPECT_EQ(Names.count(Name), 1);
        EXPECT_EQ(Sizes[Name], Section.getSize());
        EXPECT_EQ(Addresses[Name], static_cast<uint64_t>(Section.getAddress().value()));
    }

    const gtirb::CodeBlock* EntryPoint = Module.getEntryPoint();
    EXPECT_EQ(EntryPoint->getAddress().value(), gtirb::Addr(ELF->entrypoint()));
}

INSTANTIATE_TEST_SUITE_P(InstantiationName, GtirbZeroBuilderTest,
                         testing::Values("inputs/hello.x64.elf"));
