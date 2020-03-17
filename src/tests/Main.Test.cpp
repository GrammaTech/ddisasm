#include <gtest/gtest.h>
#include "../AuxDataSchema.h"

void registerTestAuxDataTypes()
{
    gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::Sccs>();
}

int main(int argc, char** argv)
{
    // Register aux data types needed by testing
    registerTestAuxDataTypes();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
