#include <gtest/gtest.h>

#include "../gtirb-builder/GtirbBuilder.h"
#include "../gtirb-decoder/DatalogLoader.h"
#include "../gtirb-decoder/DatalogProgram.h"

class DatalogLoaderTest : public ::testing::TestWithParam<const char*>
{
};

class TestSymbolDecoder : public SymbolDecoder
{
};

TEST_P(DatalogLoaderTest, loadElfGtirb)
{
    auto GTIRB = GtirbBuilder::read(GetParam());
    EXPECT_TRUE(GTIRB);

    auto Loader = DatalogLoader("test", {
                                            FormatDecoder{},
                                            TestSymbolDecoder{},
                                            SectionDecoder{},
                                            AuxDataDecoder{},
                                        });
}

INSTANTIATE_TEST_SUITE_P(GtirbDecoderTests, DatalogLoaderTest,
                         testing::Values("inputs/hello.x64.elf"));
