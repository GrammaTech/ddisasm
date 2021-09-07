#include <gtest/gtest.h>

#include <LIEF/LIEF.hpp>
#include <gtirb/gtirb.hpp>

#include "../gtirb-builder/ElfReader.h"
#include "../gtirb-builder/GtirbBuilder.h"

using GTIRB = GtirbBuilder::GTIRB;

TEST(RawReaderTest, read_gtirb)
{
    {
        // Read binary to GTIRB.
        gtirb::ErrorOr<GTIRB> GTIRB = GtirbBuilder::read("inputs/hello.x64.elf");
        EXPECT_TRUE(GTIRB);

        // Save GTIRB to file.
        std::ofstream Stream("inputs/hello.gtirb", std::ios::out | std::ios::binary);
        GTIRB->IR->save(Stream);
    }
    {
        // Read GTIRB.
        gtirb::ErrorOr<GTIRB> GTIRB = GtirbBuilder::read("inputs/hello.gtirb");
        EXPECT_TRUE(GTIRB);
    }
}
