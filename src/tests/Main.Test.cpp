#include <gtest/gtest.h>

#include "../AuxDataSchema.h"

void registerTestAuxDataTypes()
{
    using namespace gtirb::schema;
    using namespace gtirb::provisional_schema;
    gtirb::AuxDataContainer::registerAuxDataType<Alignment>();
    gtirb::AuxDataContainer::registerAuxDataType<Comments>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionBlocks>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionNames>();
    gtirb::AuxDataContainer::registerAuxDataType<Padding>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolForwarding>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolInfo>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolTabIdxInfo>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolVersions>();
    gtirb::AuxDataContainer::registerAuxDataType<BinaryType>();
    gtirb::AuxDataContainer::registerAuxDataType<ArchInfo>();
    gtirb::AuxDataContainer::registerAuxDataType<Sccs>();
    gtirb::AuxDataContainer::registerAuxDataType<Relocations>();
    gtirb::AuxDataContainer::registerAuxDataType<DynamicEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<Encodings>();
    gtirb::AuxDataContainer::registerAuxDataType<SectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<SectionIndex>();
    gtirb::AuxDataContainer::registerAuxDataType<CfiDirectives>();
    gtirb::AuxDataContainer::registerAuxDataType<Libraries>();
    gtirb::AuxDataContainer::registerAuxDataType<LibraryPaths>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolicExpressionSizes>();
    gtirb::AuxDataContainer::registerAuxDataType<DdisasmVersion>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfStackSize>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfStackExec>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSoname>();
}

int main(int argc, char** argv)
{
    // Register aux data types needed by testing
    registerTestAuxDataTypes();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
