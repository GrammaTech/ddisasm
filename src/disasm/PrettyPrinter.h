#pragma once

#include <cstdint>
#include <iosfwd>
#include <list>
#include <map>
#include <string>
#include <vector>

#include "DisasmData.h"
#include "DataGroup.h"

///
/// \class PrettyPrinter
///
/// Port of the prolog pretty printer.
///
class PrettyPrinter
{
public:
    PrettyPrinter();

    void setDebug(bool x);
    bool getDebug() const;

    ///
    /// Pretty print to the given file name.
    ///
    std::string prettyPrint(DisasmData* x);

protected:
    /// Constants to reduce (eliminate) magical strings inside the printer.
    const std::string StrOffset{"OFFSET"};
    const std::string StrRIP{"[RIP]"};
    const std::string StrZeroByte{".byte 0x00"};
    const std::string StrNOP{"nop"};
    const std::string StrSection{".section"};
    const std::string StrSectionText{".text"};
    const std::string StrSectionGlobal{".globl"};
    const std::string StrSectionType{".type"};
    const std::string StrTab{"          "};

    const std::array<std::string, 7> AsmSkipSection{
        {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt"}};
        
    const std::array<std::string, 7> AsmSkipFunction{
        {"_start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux",
         "frame_dummy", "__libc_csu_fini", "__libc_csu_init"}};

    // Name, Alignment.
    const std::array<std::pair<std::string, int>, 7> DataSectionDescriptors {{
        {".got", 8}, //
        {".got.plt",8}, //
        {".data.rel.ro",8}, //
        {".init_array",8}, //
        {".fini_array",8}, //
        {".rodata",16}, //
        {".data",16} //
    }};

    void printBar(bool heavy = true);
    void printBlock(const Block& x);
    void printEA(uint64_t ea);
    void printFunctionHeader(uint64_t ea);
    void printHeader();
    void printInstruction(uint64_t ea);
    void printInstructionNop();
    void printLabel(uint64_t ea);
    void printSectionHeader(const std::string& x, uint64_t alignment = 0);
    void printOperandList(const Instruction* const x);

    void printDataGroups();
    void printDataGroupLabelMarker(const DataGroupLabelMarker* const x);
    void printDataGroupPLTReference(const DataGroupPLTReference* const x);
    void printDataGroupPointer(const DataGroupPointer* const x);
    void printDataGroupPointerDiff(const DataGroupPointerDiff* const x);
    void printDataGroupString(const DataGroupString* const x);
    void printDataGroupRawByte(const DataGroupRawByte* const x);

    std::string buildOperand(uint64_t operand, uint64_t ea, uint64_t index);
    std::string buildOpRegdirect(const OpRegdirect* const op, uint64_t ea, uint64_t index);
    std::string buildOpImmediate(const OpImmediate* const op, uint64_t ea, uint64_t index);
    std::string buildOpIndirect(const OpIndirect* const op, uint64_t ea, uint64_t index);
    std::string buildAdjustMovedDataLabel(uint64_t ea, uint64_t value);
    void buildDataGroups();

    void condPrintGlobalSymbol(uint64_t ea);
    void condPrintSectionHeader(const Block& x);

    bool skipEA(const uint64_t x) const;

    // % avoid_reg_name_conflics
    std::string avoidRegNameConflicts(const std::string& x);
    void printZeros(uint64_t x);

    std::pair<std::string, char> getOffsetAndSign(int64_t offset, uint64_t ea, uint64_t index) const;
    bool getIsPointerToExcludedCode(DataGroup* dg, DataGroup* dgNext);

    // Static utility functions.

    static int64_t GetNeededPadding(int64_t alignment, int64_t currentAlignment,
                                    int64_t requiredAlignment);
    static std::string GetSymbolToPrint(uint64_t x);
    static bool GetIsNullReg(const std::string& x);

private:
    struct DataSection
    {
        Section SectionPtr;
        std::vector<std::unique_ptr<DataGroup>> DataGroups;
        int Alignment{0};
    };

    std::vector<DataSection> dataSections;

    std::stringstream ofs;
    DisasmData* disasm{nullptr};
    bool debug{false};
};
