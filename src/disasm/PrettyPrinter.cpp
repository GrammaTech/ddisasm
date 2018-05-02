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
    BlockAreaComment(std::stringstream& ss, std::string m = std::string{},
                     std::function<void()> f = []() {})
        : ofs{ss}, message{std::move(m)}, func{std::move(f)}
    {
        ofs << std::endl;

        if(message.empty() == false)
        {
            ofs << "# BEGIN - " << this->message << std::endl;
        }

        func();
    }

    ~BlockAreaComment()
    {
        func();

        if(message.empty() == false)
        {
            ofs << "# END   - " << this->message << std::endl;
        }

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

    for(int i = 0; i < 8; i++)
    {
        this->ofs << PrettyPrinter::StrNOP << std::endl;
    }
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

    if(x == PrettyPrinter::StrSectionText)
    {
        ofs << PrettyPrinter::StrSectionText << std::endl;
    }
    else
    {
        this->ofs << PrettyPrinter::StrSection << " " << x << std::endl;
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

        this->ofs << PrettyPrinter::StrSectionGlobal << " " << name << std::endl;
        this->ofs << PrettyPrinter::StrSectionType << " " << name << ", @function" << std::endl;
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
        this->ofs << PrettyPrinter::StrSectionGlobal << " " << name << std::endl;
        this->ofs << name << ":" << std::endl;
    }
}

void PrettyPrinter::printInstruction(uint64_t ea)
{
    // TODO // Maybe print random nop's.
    this->printEA(ea);

    auto inst = this->disasm->getInstruction(ea);
    auto opcode = str_tolower(inst->Opcode);
    opcode = DisasmData::AdaptOpcode(opcode);

    this->ofs << " " << opcode << " ";
    this->printOperandList(inst);

    /// TAKE THIS OUT ///
    this->ofs << std::endl;
}

void PrettyPrinter::printInstructionNop()
{
    this->ofs << PrettyPrinter::StrNOP << std::endl;
}

void PrettyPrinter::printEA(uint64_t ea)
{
    this->ofs << "          ";

    if(this->getDebug() == true)
    {
        this->ofs << std::hex << ea << ": ";
    }
}

void PrettyPrinter::printOperandList(const Instruction* const x)
{
    const auto strOp1 = this->buildOperand(x->Op1, x->EA, 1);
    const auto strOp2 = this->buildOperand(x->Op2, x->EA, 2);
    const auto strOp3 = this->buildOperand(x->Op3, x->EA, 3);

    if(strOp3.empty() == false)
    {
        this->ofs << strOp3 << ", " << strOp1 << ", " << strOp2;
    }
    else if(strOp2.empty() == false)
    {
        this->ofs << strOp2 << ", " << strOp1;
    }
    else
    {
        this->ofs << strOp1;
    }
}

std::string PrettyPrinter::buildOperand(uint64_t operand, uint64_t ea, uint64_t index)
{
    auto opReg = this->disasm->getOpRegdirect(operand);
    if(opReg != nullptr)
    {
        return this->buildOpRegdirect(opReg, ea, index);
    }

    auto opImm = this->disasm->getOpImmediate(operand);
    if(opImm != nullptr)
    {
        return this->buildOpImmediate(opImm, ea, index);
    }

    auto opInd = this->disasm->getOpIndirect(operand);
    if(opInd != nullptr)
    {
        return this->buildOpIndirect(opInd, ea, index);
    }

    return std::string{};
}

std::string PrettyPrinter::buildOpRegdirect(const OpRegdirect* const op, uint64_t /*ea*/,
                                            uint64_t /*index*/)
{
    return DisasmData::AdaptRegister(op->Register);
}

std::string PrettyPrinter::buildOpImmediate(const OpImmediate* const op, uint64_t ea,
                                            uint64_t index)
{
    auto pltReference = this->disasm->getPLTReference(ea);
    if(pltReference != nullptr)
    {
        return PrettyPrinter::StrOffset + " " + pltReference->Name;
    }

    auto directCall = this->disasm->getDirectCall(ea);
    if(directCall != nullptr && this->skipEA(directCall->Destination) == false)
    {
        const auto functionName = this->disasm->getFunctionName(directCall->Destination);

        if(functionName.empty() == true)
        {
            return std::to_string(directCall->Destination);
        }

        return functionName;
    }

    auto moveLabel = this->disasm->getMovedLabel(ea);
    if(moveLabel != nullptr)
    {
        assert(moveLabel->Offset1 == op->Immediate);
        auto diff = moveLabel->Offset1 - moveLabel->Offset2;
        auto symOffset2 = GetSymbolToPrint(moveLabel->Offset2);
        std::stringstream ss;
        ss << PrettyPrinter::StrOffset << " " << symOffset2 << "+" << diff;
        return ss.str();
    }

    auto symbolicOperand = this->disasm->getSymbolicOperand(ea, index);
    if(symbolicOperand != nullptr)
    {
        if(index == 1)
        {
            auto ref = this->disasm->getGlobalSymbolReference(op->Immediate);
            if(ref.empty() == false)
            {
                return PrettyPrinter::StrOffset + " " + ref;
            }
            else
            {
                return PrettyPrinter::StrOffset + " " + GetSymbolToPrint(op->Immediate);
            }
        }

        return GetSymbolToPrint(op->Immediate);
    }

    return std::to_string(op->Immediate);
}

std::string PrettyPrinter::buildOpIndirect(const OpIndirect* const op, uint64_t ea, uint64_t index)
{
    const auto sizeName = DisasmData::GetSizeName(op->Size);

    auto putSegmentRegister = [op](const std::string& term) {
        if(PrettyPrinter::GetIsNullReg(op->SReg) == false)
        {
            return op->SReg + ":[" + term + "]";
        }

        return "[" + term + "]";
    };

    if(op->Offset == 0)
    {
        if(PrettyPrinter::GetIsNullReg(op->SReg) && PrettyPrinter::GetIsNullReg(op->Reg1)
           && PrettyPrinter::GetIsNullReg(op->Reg2))
        {
            return sizeName + std::string{" [0]"};
        }
    }

    if(op->Reg1 == std::string{"RIP"} && op->Multiplier == 1)
    {
        if(PrettyPrinter::GetIsNullReg(op->SReg) && PrettyPrinter::GetIsNullReg(op->Reg2))
        {
            auto symbolicOperand = this->disasm->getSymbolicOperand(ea, index);
            if(symbolicOperand != nullptr)
            {
                auto instruction = this->disasm->getInstruction(ea);
                auto address = ea + op->Offset + instruction->Size;
                auto symbol = this->disasm->getGlobalSymbolReference(address);

                if(symbol.empty() == false)
                {
                    return sizeName + " " + symbol + PrettyPrinter::StrRIP;
                }
                else
                {
                    auto symbolToPrint = GetSymbolToPrint(address);
                    return sizeName + " " + symbolToPrint + PrettyPrinter::StrRIP;
                }
            }
        }
    }

    if(PrettyPrinter::GetIsNullReg(op->Reg1) == false
       && PrettyPrinter::GetIsNullReg(op->Reg2) == true && op->Offset == 0)
    {
        auto adapted = DisasmData::AdaptRegister(op->Reg1);
        return sizeName + " " + putSegmentRegister(adapted);
    }

    return std::string{};
}

bool PrettyPrinter::skipEA(const uint64_t x) const
{
    const auto sections = this->disasm->getSection();

    for(const auto& s : *sections)
    {
        const auto found = std::find(std::begin(PrettyPrinter::AsmSkipSection),
                                     std::end(PrettyPrinter::AsmSkipSection), s.Name);

        if(found != std::end(PrettyPrinter::AsmSkipSection))
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
        const auto found = std::find(std::begin(PrettyPrinter::AsmSkipFunction),
                                     std::end(PrettyPrinter::AsmSkipFunction), xFunctionName);
        return found != std::end(PrettyPrinter::AsmSkipFunction);
    }

    return false;
}

void PrettyPrinter::printZeros(uint64_t x)
{
    for(uint64_t i = 0; i < x; i++)
    {
        this->ofs << PrettyPrinter::StrZeroByte << std::endl;
    }
}

std::string PrettyPrinter::GetSymbolToPrint(uint64_t x)
{
    std::stringstream ss;
    ss << ".L_" << std::hex << x;
    return ss.str();
}

int64_t PrettyPrinter::GetNeededPadding(int64_t alignment, int64_t currentAlignment,
                                        int64_t requiredAlignment)
{
    if(alignment >= currentAlignment)
    {
        return alignment - currentAlignment;
    }

    return (alignment + requiredAlignment) - currentAlignment;
}

bool PrettyPrinter::GetIsNullReg(const std::string& x)
{
    const std::vector<std::string> adapt{"NullReg64", "NullReg32", "NullReg16", "NullSReg"};

    const auto found = std::find(std::begin(adapt), std::end(adapt), x);
    return (found != std::end(adapt));
}
