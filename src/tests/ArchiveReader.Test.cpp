#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <fstream>
#include <string>

#include "../gtirb-builder/ArchiveReader.h"

TEST(ArchiveReaderTest, Basic)
{
    ArchiveReader Reader("inputs/ar/basic.a");

    std::vector<std::string> FileNames = {"file1", "file2"};
    std::vector<std::string> Contents = {"contents1", "contents2"};
    EXPECT_EQ(Reader.Files.size(), FileNames.size());

    unsigned int Index = 0;
    for(auto& Object : Reader.Files)
    {
        EXPECT_EQ(Object.FileName, FileNames[Index]);

        std::vector<uint8_t> FileData;
        Reader.readFile(Object, FileData);

        std::string FileDataStr(FileData.begin(), FileData.end());
        EXPECT_EQ(FileDataStr, Contents[Index]);
        Index++;
    }
}

TEST(ArchiveReaderTest, Empty)
{
    ArchiveReader Reader("inputs/ar/empty.a");
    EXPECT_EQ(Reader.Files.size(), 0);
}

TEST(ArchiveReaderTest, BSD)
{
    ArchiveReader Reader("inputs/ar/bsd.a");

    std::vector<std::string> FileNames = {
        "long_archive_member_name",
        "file",
    };
    EXPECT_EQ(Reader.Files.size(), FileNames.size());

    unsigned int Index = 0;
    for(auto& Object : Reader.Files)
    {
        EXPECT_EQ(Object.FileName, FileNames[Index++]);
    }
}

TEST(ArchiveReaderTest, GNU)
{
    ArchiveReader Reader("inputs/ar/gnu.a");

    std::vector<std::string> FileNames = {
        "long_archive_member_name",
        "file",
        "other_archive_member_name",
    };
    EXPECT_EQ(Reader.Files.size(), FileNames.size());

    unsigned int Index = 0;
    for(auto& Object : Reader.Files)
    {
        EXPECT_EQ(Object.FileName, FileNames[Index++]);
    }
}
