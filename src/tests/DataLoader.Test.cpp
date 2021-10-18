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

    //
    {
        // Add test data.
        std::vector<uint8_t> Bytes = {
            0x00, 0x00, 0x00, 0x00,                                     // null
            0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, // "hello"
            0x00, 0x00                                                  // null
        };
        gtirb::ByteInterval* ByteInterval =
            gtirb::ByteInterval::Create(C, gtirb::Addr(0x1000), Bytes.begin(), Bytes.end());

        // Load the test data.
        DataFacts Facts;
        Facts.Min = gtirb::Addr(0x1000);
        Facts.Max = gtirb::Addr(0x2000);

        DataLoaderTest Loader(DataLoaderTest::Pointer::DWORD, DataLoaderTest::Endian::LITTLE);
        Loader.load(*ByteInterval, Facts);

        // Check the loaded facts.
        EXPECT_EQ(Facts.Utf16.size(), 1);
        EXPECT_EQ(Facts.Utf16[0].Addr, gtirb::Addr(0x1004));
        EXPECT_EQ(Facts.Utf16[0].Size, 12);
        EXPECT_EQ(Facts.Utf16[0].Characters, 5);
    }
}
