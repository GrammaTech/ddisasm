#include <gtest/gtest.h>

#include "../gtirb-builder/GtirbBuilder.h"
#include "../gtirb-decoder/DatalogLoader.h"
#include "../gtirb-decoder/DatalogProgram.h"

class DatalogLoaderTest : public ::testing::TestWithParam<const char *>
{
};

class TestDecoder : public GtirbDecoder
{
    void load(const gtirb::Module &M){};
    void populate(DatalogProgram &P){};
};

TEST_P(DatalogLoaderTest, loadElfGtirb)
{
    // Create GTIRB.
    auto GTIRB = GtirbBuilder::read(GetParam());
    EXPECT_TRUE(GTIRB);
    gtirb::Module &Module = *(GTIRB->IR->modules().begin());

    // Load GTIRB.
    DatalogLoader TestLoader = DatalogLoader("test");
    TestLoader.add<TestDecoder>();
    TestLoader.decode(Module);

    // Build Souffle context.
    std::optional<DatalogProgram> TestProgram = TestLoader.program();
}

INSTANTIATE_TEST_SUITE_P(GtirbDecoderTests, DatalogLoaderTest,
                         testing::Values("inputs/hello.x64.elf"));
