#include <gtest/gtest.h>

#include <gtirb/gtirb.hpp>

#include "../BinaryReader.h"
#include "../LIEFBinaryReader.h"

class LIEFBinaryReaderTest : public ::testing::TestWithParam<const char*>
{
protected:
    void SetUp() override
    {
        const std::string& Path(GetParam());
        Binary = std::make_unique<LIEFBinaryReader>(Path);
    }
    std::unique_ptr<BinaryReader> Binary;
};

TEST_P(LIEFBinaryReaderTest, is_valid)
{
    EXPECT_TRUE(Binary->is_valid());
}

TEST_P(LIEFBinaryReaderTest, get_binary_format)
{
    EXPECT_EQ(Binary->get_binary_format(), gtirb::FileFormat::ELF);
}

TEST_P(LIEFBinaryReaderTest, get_binary_type)
{
    EXPECT_EQ(Binary->get_binary_type(), "DYN");
}

TEST_P(LIEFBinaryReaderTest, get_entry_point)
{
    EXPECT_GT(Binary->get_entry_point(), 0);
}

const char* INPUT_BINARIES[] = {"inputs/hello.x64.elf"};
INSTANTIATE_TEST_SUITE_P(InstantiationName, LIEFBinaryReaderTest,
                         testing::ValuesIn(INPUT_BINARIES));
