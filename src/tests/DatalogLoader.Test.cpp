#include <gtest/gtest.h>

#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>

#include "../gtirb-builder/GtirbBuilder.h"
#include "../gtirb-decoder/DatalogLoader.h"
#include "../gtirb-decoder/DatalogProgram.h"
#include "../gtirb-decoder/targets/X64Decoder.h"

class DatalogLoaderTest : public ::testing::TestWithParam<const char*>
{
protected:
    void SetUp() override
    {
        auto GTIRB = GtirbBuilder::read(GetParam());
        Context = std::move(GTIRB->Context);
        IR = GTIRB->IR;
        Module = &*(GTIRB->IR->modules().begin());
    }
    std::unique_ptr<gtirb::Context> Context;
    gtirb::IR* IR;
    gtirb::Module* Module;
};

class TestDecoder : public GtirbDecoder
{
    void load(const gtirb::Module& M){};
    void populate(DatalogProgram& P){};
};

TEST_P(DatalogLoaderTest, add_test_decoder)
{
    // Load GTIRB.
    DatalogLoader TestLoader = DatalogLoader("souffle_no_return");
    TestLoader.add<TestDecoder>();
    TestLoader.decode(*Module);

    // Build Souffle context.
    std::optional<DatalogProgram> TestProgram = TestLoader.program();
    EXPECT_TRUE(TestProgram);
}

TEST_P(DatalogLoaderTest, format_decoder)
{
    // Load GTIRB.
    // DatalogLoader TestLoader = DatalogLoader("souffle_disasm_x64");
    // TestLoader.add<FormatDecoder>();
    // TestLoader.decode(*Module);

    // Build Souffle context.
    // std::optional<DatalogProgram> TestProgram = TestLoader.program();
    // EXPECT_TRUE(TestProgram);

    // Check Souffle relation.
    // souffle::SouffleProgram *Program = **TestProgram;
    // {
    //     auto *Relation = Program->getRelation("binary_type");
    // }
    // {
    //     auto *Relation = Program->getRelation("binary_format");
    // }
    // {
    //     auto *Relation = Program->getRelation("entry_point");
    // }

    // ElfX64Loader Loader;
    // Loader.decode(*Module);

    // // Build Souffle context.
    // std::optional<DatalogProgram> Program = Loader.program();
    // EXPECT_TRUE(Program);
}

INSTANTIATE_TEST_SUITE_P(GtirbDecoderTests, DatalogLoaderTest,
                         testing::Values("inputs/hello.x64.elf"));
