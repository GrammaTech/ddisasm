#include <gtest/gtest.h>

#include <gtirb/gtirb.hpp>

#include "../gtirb-decoder/core/DataLoader.h"

class DataLoaderTest : public DataLoader
{
public:
    using DataLoader::Endian;
    using DataLoader::Pointer;

    DataLoaderTest(Pointer N, Endian E) : DataLoader(N, E){};

    void load(const gtirb::ByteInterval& Bytes, DataFacts& Facts) override
    {
        DataLoader::load(Bytes, Facts);
    }
};

TEST(DataLoaderTests, load_utf16)
{
    // Create test GTIRB.
    gtirb::Context C;
    gtirb::IR* I = gtirb::IR::Create(C);
    gtirb::Module* M = I->addModule(C, "test");

    // Add test data.
    std::vector<uint8_t> Bytes = {
        0x00, 0x00, 0x00, 0x00,                                  // null
        0x68, 0x0,  0x65, 0x0,  0x6c, 0x0, 0x6c, 0x0, 0x6f, 0x0, // "hello"
        0x00, 0x00                                               // null
    };
    gtirb::ByteInterval* ByteInterval =
        gtirb::ByteInterval::Create(C, gtirb::Addr(0x1000), Bytes.begin(), Bytes.end());
    EXPECT_TRUE(ByteInterval->getInitializedSize() == Bytes.size());
    EXPECT_TRUE(ByteInterval->getInitializedSize() > 0);

    // Load the test data.
    DataLoaderTest Loader(DataLoaderTest::Pointer::DWORD, DataLoaderTest::Endian::LITTLE);

    DataFacts Facts;
    Facts.Min = gtirb::Addr(0x1000);
    Facts.Max = gtirb::Addr(0x2000);
    Loader.load(*ByteInterval, Facts);

    // Check the loaded facts.
    EXPECT_EQ(Facts.Utf16.size(), 1);
}
