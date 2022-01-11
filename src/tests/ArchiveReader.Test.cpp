#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <fstream>
#include <string>

#include "../gtirb-builder/ArchiveReader.h"

namespace fs = boost::filesystem;

TEST(ArchiveReaderTest, Basic)
{
    auto TmpDir = fs::temp_directory_path();
    ArchiveReader Reader("inputs/ar/basic.a");

    std::vector<std::string> FileNames = {"file1", "file2"};
    std::vector<std::string> Contents = {"contents1", "contents2"};
    EXPECT_EQ(Reader.Files().size(), FileNames.size());

    unsigned int Index = 0;
    for(auto& Object : Reader.Files())
    {
        EXPECT_EQ(Object->FileName, FileNames[Index]);

        std::string ObjectPath = (TmpDir / fs::unique_path()).string();
        Object->Extract(ObjectPath);

        std::ifstream Stream(ObjectPath);
        std::string FileContent((std::istreambuf_iterator<char>(Stream)),
                                (std::istreambuf_iterator<char>()));

        EXPECT_EQ(FileContent, Contents[Index]);

        Stream.close();
        fs::remove(ObjectPath);

        Index++;
    }
}

TEST(ArchiveReaderTest, Empty)
{
    ArchiveReader Reader("inputs/ar/empty.a");
    EXPECT_EQ(Reader.Files().size(), 0);
}

TEST(ArchiveReaderTest, BSD)
{
    ArchiveReader Reader("inputs/ar/bsd.a");

    std::vector<std::string> FileNames = {
        "long_archive_member_name",
        "file",
    };
    EXPECT_EQ(Reader.Files().size(), FileNames.size());

    unsigned int Index = 0;
    for(auto& Object : Reader.Files())
    {
        EXPECT_EQ(Object->FileName, FileNames[Index++]);
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
    EXPECT_EQ(Reader.Files().size(), FileNames.size());

    unsigned int Index = 0;
    for(auto& Object : Reader.Files())
    {
        EXPECT_EQ(Object->FileName, FileNames[Index++]);
    }
}
