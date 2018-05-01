#pragma once

#include <cstdint>
#include <iosfwd>
#include <list>
#include <map>
#include <string>
#include <vector>

#include "DisasmData.h"

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
    void printBar(bool heavy = true);
    void printBlock(const Block& x);
    void printEA(uint64_t ea);
    void printFunctionHeader(uint64_t ea);
    void printHeader();
    void printInstruction(uint64_t ea);
    void printInstructionNop();
    void printLabel(uint64_t ea);
    void printSectionHeader(const std::string& x);

    void condPrintGlobalSymbol(uint64_t ea);
    void condPrintSectionHeader(const Block& x);

    bool skipEA(const uint64_t x) const;

    // % avoid_reg_name_conflics
    std::string avoidRegNameConflicts(const std::string& x);
    void printZeros(uint64_t x);

    // Static utility functions.

    static int64_t GetNeededPadding(int64_t alignment, int64_t currentAlignment, int64_t requiredAlignment);

private:
    DisasmData* disasm{nullptr};
    std::stringstream ofs;

    std::vector<std::string> asm_skip_section;
    std::vector<std::string> asm_skip_function;

    bool debug{false};
};
