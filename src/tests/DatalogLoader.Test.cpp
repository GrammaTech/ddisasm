#include <gtest/gtest.h>

#include "../gtirb-builder/GtirbBuilder.h"
#include "../gtirb-decoder/DatalogLoader.h"
#include "../gtirb-decoder/DatalogProgram.h"
#include "../gtirb-decoder/DatalogUtils.h"

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

class TestLoader
{
public:
    TestLoader(){};
    void operator()(const gtirb::Module& Module, DatalogProgram& Program)
    {
        auto Tuples = {relations::SccIndex{0, 0, gtirb::Addr(0)}};
        Program.insert("in_scc", Tuples);
    }
};

void TestLoaderFunction(const gtirb::Module& Module, DatalogProgram& Program)
{
    auto Tuples = {relations::SccIndex{1, 1, gtirb::Addr(1)}};
    Program.insert("in_scc", Tuples);
}

TEST_P(DatalogLoaderTest, build_test_loader)
{
    // Load GTIRB.
    DatalogLoader Loader = DatalogLoader("souffle_no_return");
    Loader.add<TestLoader>();
    Loader.add(TestLoaderFunction);

    // Build Souffle context.
    std::optional<DatalogProgram> TestProgram = Loader(*Module);
    EXPECT_TRUE(TestProgram);
    {
        auto* Relation = (**TestProgram)->getRelation("in_scc");
        EXPECT_EQ(Relation->size(), 2);
    }
}

INSTANTIATE_TEST_SUITE_P(GtirbDecoderTests, DatalogLoaderTest,
                         testing::Values("inputs/hello.x64.elf"));
