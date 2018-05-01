#include "PrettyPrinter.h"
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include "DisasmData.h"

///
/// Pring a comment that automatically scopes.
///
class BlockAreaComment
{
public:
    BlockAreaComment(std::stringstream& ss, std::string m, std::function<void()> f = []() {})
        : ofs{ss}, message{std::move(m)}, func{std::move(f)}
    {
        ofs << std::endl;
        ofs << "# BEGIN - " << this->message << std::endl;
        func();
    }

    ~BlockAreaComment()
    {
        func();
        ofs << "# END   - " << this->message << std::endl;
        ofs << std::endl;
    }

    std::stringstream& ofs;
    const std::string message;
    std::function<void()> func;
};

std::string str_tolower(std::string s)
{
    std::transform(
        s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); } // correct
        );
    return s;
}

PrettyPrinter::PrettyPrinter()
{
    this->asm_skip_section = {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt"};
    this->asm_skip_function = {
        "_start",      "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux",
        "frame_dummy", "__libc_csu_fini",      "__libc_csu_init"};
}

void PrettyPrinter::setDebug(bool x)
{
    this->debug = x;
}

bool PrettyPrinter::getDebug() const
{
    return this->debug;
}

std::string PrettyPrinter::prettyPrint(DisasmData* x)
{
    this->disasm = x;
    this->ofs.clear();

    this->printHeader();

    auto blocks = this->disasm->getCodeBlocks();

    if(this->getDebug() == true)
    {
        DisasmData::AdjustPadding(blocks);
    }

    for(const auto& b : blocks)
    {
        this->printBlock(b);
    }

    return this->ofs.str();
}

void PrettyPrinter::printHeader()
{
    this->printBar();
    this->ofs << ".intel_syntax noprefix" << std::endl;
    this->printBar();
    this->ofs << "" << std::endl;
    this->ofs << "nop" << std::endl;
    this->ofs << "nop" << std::endl;
    this->ofs << "nop" << std::endl;
    this->ofs << "nop" << std::endl;
    this->ofs << "nop" << std::endl;
    this->ofs << "nop" << std::endl;
    this->ofs << "nop" << std::endl;
    this->ofs << "nop" << std::endl;
}

void PrettyPrinter::printBlock(const Block& x)
{
    if(this->skipEA(x.StartingAddress) == false)
    {
        if(x.Instructions.empty() == false)
        {
            this->condPrintSectionHeader(x);
            this->printFunctionHeader(x.StartingAddress);
            this->printLabel(x.StartingAddress);

            for(auto inst : x.Instructions)
            {
                this->printInstruction(inst);
            }
        }
        else
        {
            const auto nopCount = x.EndingAddress - x.StartingAddress;
            this->ofs << std::endl;

            const auto bac = BlockAreaComment(this->ofs, "No instruciton padding.");

            // Fill in the correct number of nops.
            for(uint64_t i = 0; i < nopCount; ++i)
            {
                this->printInstructionNop();
            }
        }
    }
}

void PrettyPrinter::condPrintSectionHeader(const Block& x)
{
    const auto sections = this->disasm->getSection();

    for(const auto& s : *sections)
    {
        if(s.StartingAddress == x.StartingAddress)
        {
            this->printSectionHeader(s.Name);
            return;
        }
    }
}

void PrettyPrinter::printSectionHeader(const std::string& x)
{
    ofs << std::endl;
    this->printBar();

    if(x == ".text")
    {
        ofs << ".text" << std::endl;
    }
    else
    {
        this->ofs << ".section " << x << std::endl;
    }

    this->printBar();
    ofs << std::endl;
}

void PrettyPrinter::printBar(bool heavy)
{
    if(heavy == true)
    {
        this->ofs << "#===================================" << std::endl;
    }
    else
    {
        this->ofs << "#-----------------------------------" << std::endl;
    }
}

void PrettyPrinter::printFunctionHeader(uint64_t ea)
{
    const auto name = this->disasm->getFunctionName(ea);

    if(name.empty() == false)
    {
        const auto bac =
            BlockAreaComment(this->ofs, "Function Header", [this]() { this->printBar(false); });

        // enforce maximum alignment
        if(ea % 8 == 0)
        {
            this->ofs << ".align 8" << std::endl;
        }
        else if(ea % 2 == 0)
        {
            this->ofs << ".align 2" << std::endl;
        }

        this->ofs << ".globl " << name << std::endl;
        this->ofs << ".type " << name << ", @function" << std::endl;
        this->ofs << name << ":" << std::endl;
    }
}

void PrettyPrinter::printLabel(uint64_t ea)
{
    this->condPrintGlobalSymbol(ea);
    this->ofs << ".L_" << std::hex << ea << ":" << std::endl;
}

void PrettyPrinter::condPrintGlobalSymbol(uint64_t ea)
{
    auto name = this->disasm->getGlobalSymbolName(ea);

    if(name.empty() == false)
    {
        this->ofs << ".globl " << name << std::endl;
        this->ofs << name << ":" << std::endl;
    }
}

void PrettyPrinter::printInstruction(uint64_t ea)
{
    // TODO // Maybe print random nop's.
    this->printEA(ea);

    const auto inst = this->disasm->getInstructionAt(ea);
    auto opcode = str_tolower(inst.Opcode);
    opcode = DisasmData::AdaptOpcode(opcode);

    this->ofs << " " << opcode;

    /// TAKE THIS OUT ///
    this->ofs << std::endl;
}

void PrettyPrinter::printInstructionNop()
{
    this->ofs << "nop" << std::endl;
}

void PrettyPrinter::printEA(uint64_t ea)
{
    this->ofs << "          ";

    if(this->getDebug() == true)
    {
        this->ofs << std::hex << ea << ": ";
    }
}

bool PrettyPrinter::skipEA(const uint64_t x) const
{
    const auto sections = this->disasm->getSection();

    for(const auto& s : *sections)
    {
        const auto found =
            std::find(std::begin(this->asm_skip_section), std::end(this->asm_skip_section), s.Name);

        if(found != std::end(this->asm_skip_section))
        {
            const auto isSkipped = ((x >= s.StartingAddress) && (x < (s.StartingAddress + s.Size)));

            if(isSkipped == true)
            {
                return true;
            }
        }
    }

    uint64_t xFunctionAddress{0};
    const auto functionEntries = this->disasm->getFunctionEntry();

    for(auto fe = std::begin(*functionEntries); fe != std::end(*functionEntries); ++fe)
    {
        auto feNext = fe;
        feNext++;

        if(x >= *fe && x < *feNext)
        {
            xFunctionAddress = *fe;
            continue;
        }
    }

    std::string xFunctionName{};
    const auto functionSymbols = this->disasm->getFunctionSymbol();

    for(auto& fs : *functionSymbols)
    {
        if(fs.EA == xFunctionAddress)
        {
            xFunctionName = fs.Name;
            continue;
        }
    }

    // if we have a function address.
    // and that funciton address has a name.
    // is that name in our skip list?

    if(xFunctionName.empty() == false)
    {
        const auto found = std::find(std::begin(this->asm_skip_function),
                                     std::end(this->asm_skip_function), xFunctionName);
        return found != std::end(this->asm_skip_function);
    }

    return false;
}
