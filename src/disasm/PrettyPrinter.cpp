#include "PrettyPrinter.h"
#include <boost/algorithm/string/replace.hpp>
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

    this->buildDataGroups();
    this->printDataGroups();

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
            this->ofs << std::endl;

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

void PrettyPrinter::printSectionHeader(const std::string& x, uint64_t alignment)
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

        if(alignment != 0)
        {
            this->ofs << ".align " << alignment << std::endl;
        }
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
    this->ofs << ".L_" << std::hex << ea << ":" << std::dec;
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
        this->ofs << std::hex << ea << ": " << std::dec;
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

    // Case 1
    if(op->Offset == 0)
    {
        if(PrettyPrinter::GetIsNullReg(op->SReg) && PrettyPrinter::GetIsNullReg(op->Reg1)
           && PrettyPrinter::GetIsNullReg(op->Reg2))
        {
            return sizeName + std::string{" [0]"};
        }
    }

    // Case 2
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

    // Case 3
    if(PrettyPrinter::GetIsNullReg(op->Reg1) == false
       && PrettyPrinter::GetIsNullReg(op->Reg2) == true && op->Offset == 0)
    {
        auto adapted = DisasmData::AdaptRegister(op->Reg1);
        return sizeName + " " + putSegmentRegister(adapted);
    }

    // Case 4
    if(PrettyPrinter::GetIsNullReg(op->Reg1) == true
       && PrettyPrinter::GetIsNullReg(op->Reg2) == true)
    {
        auto symbol = this->disasm->getGlobalSymbolReference(op->Offset);
        if(symbol.empty() == false)
        {
            return sizeName + putSegmentRegister(symbol);
        }

        auto offsetAndSign = this->getOffsetAndSign(op->Offset, ea, index);
        std::string term = std::string{offsetAndSign.second} + offsetAndSign.first;
        return sizeName + " " + putSegmentRegister(term);
    }

    // Case 5
    if(PrettyPrinter::GetIsNullReg(op->Reg2) == true)
    {
        auto adapted = DisasmData::AdaptRegister(op->Reg1);
        auto offsetAndSign = this->getOffsetAndSign(op->Offset, ea, index);
        std::string term = adapted + std::string{offsetAndSign.second} + offsetAndSign.first;
        return sizeName + " " + putSegmentRegister(term);
    }

    // Case 6
    if(PrettyPrinter::GetIsNullReg(op->Reg1) == true)
    {
        auto adapted = DisasmData::AdaptRegister(op->Reg2);
        auto offsetAndSign = this->getOffsetAndSign(op->Offset, ea, index);
        std::string term = adapted + "*" + std::to_string(op->Multiplier)
                           + std::string{offsetAndSign.second} + offsetAndSign.first;
        return sizeName + " " + putSegmentRegister(term);
    }

    // Case 7
    if(op->Offset == 0)
    {
        auto adapted1 = DisasmData::AdaptRegister(op->Reg1);
        auto adapted2 = DisasmData::AdaptRegister(op->Reg2);
        std::string term = adapted1 + "+" + adapted2 + "*" + std::to_string(op->Multiplier);
        return sizeName + " " + putSegmentRegister(term);
    }

    // Case 8
    auto adapted1 = DisasmData::AdaptRegister(op->Reg1);
    auto adapted2 = DisasmData::AdaptRegister(op->Reg2);
    auto offsetAndSign = this->getOffsetAndSign(op->Offset, ea, index);
    std::string term = adapted1 + "+" + adapted2 + "*" + std::to_string(op->Multiplier)
                       + std::string{offsetAndSign.second} + offsetAndSign.first;
    return sizeName + " " + putSegmentRegister(term);
}

std::string PrettyPrinter::buildAdjustMovedDataLabel(uint64_t ea, uint64_t value)
{
    std::stringstream ss;
    ss << ".L_" << std::hex << value;

    auto moved = this->disasm->getMovedDataLabel(ea);
    if(moved != nullptr)
    {
        assert(value == moved->Old);

        auto diff = value - moved->New;
        ss << "+" << diff << std::dec;
    }

    return ss.str();
}

void PrettyPrinter::buildDataGroups()
{
    for(auto s : *this->disasm->getSection())
    {
        const auto foundDataSection =
            std::find_if(std::begin(DataSectionDescriptors), std::end(DataSectionDescriptors),
                         [s](const auto& dsd) { return dsd.first == s.Name; });

        const auto foundSkipSection = std::find(std::begin(PrettyPrinter::AsmSkipSection),
                                                std::end(PrettyPrinter::AsmSkipSection), s.Name);

        if(foundDataSection != std::end(DataSectionDescriptors)
           && (foundSkipSection == std::end(PrettyPrinter::AsmSkipSection) || this->debug == true))
        {
            DataSection dataSection;
            dataSection.SectionPtr = s;
            dataSection.Alignment = foundDataSection->second;

            const uint64_t startingAddress = s.StartingAddress;
            std::vector<uint8_t> bytes;

            auto dataBytes = this->disasm->getDataByte();
            auto dataIt = std::find(std::begin(*dataBytes), std::end(*dataBytes), startingAddress);

            for(size_t i = 0; i < s.Size; ++i)
            {
                bytes.push_back(dataIt->Content);
                ++dataIt;
            }

            for(auto currentAddr = startingAddress; currentAddr < startingAddress + s.Size;
                currentAddr++)
            {
                // Insert a marker for labeled data?
                const auto foundLabeledData =
                    std::find(std::begin(*this->disasm->getLabeledData()),
                              std::end(*this->disasm->getLabeledData()), currentAddr);
                if(foundLabeledData != std::end(*this->disasm->getLabeledData()))
                {
                    auto dataGroup = std::make_unique<DataGroupLabelMarker>(currentAddr);
                    dataSection.DataGroups.push_back(std::move(dataGroup));
                }

                // Case 1, 2, 3
                const auto symbolic = this->disasm->getSymbolicData(currentAddr);
                if(symbolic != nullptr)
                {
                    // Case 1
                    const auto pltReference = this->disasm->getPLTReference(currentAddr);
                    if(pltReference != nullptr)
                    {
                        auto dataGroup = std::make_unique<DataGroupPLTReference>(currentAddr);
                        dataGroup->Function = pltReference->Name;
                        dataSection.DataGroups.push_back(std::move(dataGroup));

                        currentAddr += 7;
                        continue;
                    }

                    // Case 2, 3
                    // There was no PLT Reference and there was no label found.
                    auto dataGroup = std::make_unique<DataGroupPointer>(currentAddr);
                    dataGroup->Content = symbolic->GroupContent;
                    dataSection.DataGroups.push_back(std::move(dataGroup));

                    currentAddr += 7;
                    continue;
                }

                // Case 4, 5
                const auto symMinusSym = this->disasm->getSymbolMinusSymbol(currentAddr);
                if(symMinusSym != nullptr)
                {
                    // Case 4, 5
                    auto dataGroup = std::make_unique<DataGroupPointerDiff>(currentAddr);
                    dataGroup->Symbol1 = symMinusSym->Symbol1;
                    dataGroup->Symbol2 = symMinusSym->Symbol2;
                    dataSection.DataGroups.push_back(std::move(dataGroup));

                    currentAddr += 3;
                    continue;
                }

                // Case 6
                const auto str = this->disasm->getString(currentAddr);
                if(str != nullptr)
                {
                    auto dataGroup = std::make_unique<DataGroupString>(currentAddr);

                    for(; currentAddr < str->End; ++currentAddr)
                    {
                        dataGroup->StringBytes.push_back(bytes[currentAddr - startingAddress]);
                    }

                    // Because the loop is going to increment this counter, don't skip a byte.
                    currentAddr--;
                    dataSection.DataGroups.push_back(std::move(dataGroup));
                    continue;
                }

                // Store raw data
                auto dataGroup = std::make_unique<DataGroupRawByte>(currentAddr);
                dataGroup->Byte = bytes[currentAddr - startingAddress];
                dataSection.DataGroups.push_back(std::move(dataGroup));
            }

            this->dataSections.push_back(std::move(dataSection));
        }
    }
}

void PrettyPrinter::printDataGroups()
{
    for(const auto& ds : this->dataSections)
    {
        // Print section header...
        this->printSectionHeader(ds.SectionPtr.Name, ds.Alignment);

        // Print data for this section...
        for(auto dg = std::begin(ds.DataGroups); dg != std::end(ds.DataGroups); ++dg)
        {
            bool exclude = false;

            if(ds.SectionPtr.Name == ".init_array" || ds.SectionPtr.Name == ".fini_array")
            {
                auto dgNext = dg;
                dgNext++;

                if(dgNext != std::end(ds.DataGroups))
                {
                    exclude = this->getIsPointerToExcludedCode(dg->get(), dgNext->get());
                }
                else
                {
                    exclude = this->getIsPointerToExcludedCode(dg->get(), nullptr);
                }
            }

            if(exclude == false)
            {
                switch((*dg)->getType())
                {
                    case DataGroup::Type::LabelMarker:
                        this->printDataGroupLabelMarker(
                            dynamic_cast<const DataGroupLabelMarker* const>(dg->get()));
                        break;
                    case DataGroup::Type::PLTReference:
                        this->ofs << PrettyPrinter::StrTab;
                        this->printDataGroupPLTReference(
                            dynamic_cast<const DataGroupPLTReference* const>(dg->get()));
                        break;
                    case DataGroup::Type::Pointer:
                        this->ofs << PrettyPrinter::StrTab;
                        this->printDataGroupPointer(
                            dynamic_cast<const DataGroupPointer* const>(dg->get()));
                        break;
                    case DataGroup::Type::PointerDiff:
                        this->ofs << PrettyPrinter::StrTab;
                        this->printDataGroupPointerDiff(
                            dynamic_cast<const DataGroupPointerDiff* const>(dg->get()));
                        break;
                    case DataGroup::Type::String:
                        this->ofs << PrettyPrinter::StrTab;
                        this->printDataGroupString(
                            dynamic_cast<const DataGroupString* const>(dg->get()));
                        break;
                    case DataGroup::Type::RawByte:
                        this->ofs << PrettyPrinter::StrTab;
                        this->printDataGroupRawByte(
                            dynamic_cast<const DataGroupRawByte* const>(dg->get()));
                        break;
                }

                // Print Comments...

                // Done.
                this->ofs << std::endl;
            }
        }

        // End label
        const auto endAddress = ds.SectionPtr.StartingAddress + ds.SectionPtr.Size;
        if(this->disasm->getSectionName(endAddress).empty() == true)
        {
            // This is no the start of a new section, so print the label.
            this->printLabel(endAddress);
            this->ofs << std::endl;
        }
    }
}

void PrettyPrinter::printDataGroupLabelMarker(const DataGroupLabelMarker* const x)
{
    this->printLabel(x->getEA());
}

void PrettyPrinter::printDataGroupPLTReference(const DataGroupPLTReference* const x)
{
    this->printEA(x->getEA());
    this->ofs << ".quad " << x->Function;
}

void PrettyPrinter::printDataGroupPointer(const DataGroupPointer* const x)
{
    auto printed = this->buildAdjustMovedDataLabel(x->getEA(), x->Content);
    this->ofs << ".quad " << printed;
}

void PrettyPrinter::printDataGroupPointerDiff(const DataGroupPointerDiff* const x)
{
    this->printEA(x->getEA());
    ofs << ".long .L_" << x->Symbol2 << "-" << x->Symbol1;
}

void PrettyPrinter::printDataGroupString(const DataGroupString* const x)
{
    auto cleanByte = [](uint8_t b) {
        std::string cleaned;
        cleaned += b;

        cleaned = boost::replace_all_copy(cleaned, "\n", "\\n");
        cleaned = boost::replace_all_copy(cleaned, "\t", "\\t");
        cleaned = boost::replace_all_copy(cleaned, "\v", "\\v");
        cleaned = boost::replace_all_copy(cleaned, "\b", "\\b");
        cleaned = boost::replace_all_copy(cleaned, "\r", "\\r");
        cleaned = boost::replace_all_copy(cleaned, "\a", "\\a");
        cleaned = boost::replace_all_copy(cleaned, "\\", "\\\\");
        cleaned = boost::replace_all_copy(cleaned, "\"", "\\\"");
        cleaned = boost::replace_all_copy(cleaned, "\0", "\\0");

        return cleaned;
    };

    this->ofs << ".string \"";

    for(auto& b : x->StringBytes)
    {
        this->ofs << cleanByte(b);
    }

    this->ofs << "\"";
}

void PrettyPrinter::printDataGroupRawByte(const DataGroupRawByte* const x)
{
    ofs << ".byte 0x" << std::hex << static_cast<uint32_t>(x->Byte) << std::dec;
}

bool PrettyPrinter::skipEA(const uint64_t x) const
{
    if(this->debug == false)
    {
        const auto sections = this->disasm->getSection();

        for(const auto& s : *sections)
        {
            const auto found = std::find(std::begin(PrettyPrinter::AsmSkipSection),
                                         std::end(PrettyPrinter::AsmSkipSection), s.Name);

            if(found != std::end(PrettyPrinter::AsmSkipSection))
            {
                const auto isSkipped =
                    ((x >= s.StartingAddress) && (x < (s.StartingAddress + s.Size)));

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

std::pair<std::string, char> PrettyPrinter::getOffsetAndSign(int64_t offset, uint64_t ea,
                                                             uint64_t index) const
{
    std::pair<std::string, char> result = {"", '+'};

    auto moveLabel = this->disasm->getMovedLabel(ea);
    if(moveLabel != nullptr)
    {
        assert(moveLabel->Offset1 == offset);
        auto diff = moveLabel->Offset1 - moveLabel->Offset2;
        auto symOffset2 = GetSymbolToPrint(moveLabel->Offset2);

        if(diff >= 0)
        {
            result.first = symOffset2 + "+" + std::to_string(diff);
            result.second = '+';
            return result;
        }
        else
        {
            result.first = symOffset2 + std::to_string(diff);
            result.second = '+';
            return result;
        }
    }

    auto symbolicOperand = this->disasm->getSymbolicOperand(ea, index);
    if(symbolicOperand != nullptr)
    {
        result.first = GetSymbolToPrint(offset);
        result.second = '+';
        return result;
    }

    if(offset < 0)
    {
        result.first = std::to_string(-offset);
        result.second = '-';
        return result;
    }

    result.first = std::to_string(offset);
    result.second = '+';
    return result;
}

bool PrettyPrinter::getIsPointerToExcludedCode(DataGroup* dg, DataGroup* dgNext)
{
    // If we have a label followed by a pointer.
    auto dgLabel = dynamic_cast<DataGroupLabelMarker*>(dg);
    if(dgLabel != nullptr)
    {
        auto dgPtr = dynamic_cast<DataGroupPointer*>(dgNext);
        if(dgPtr != nullptr)
        {
            return this->skipEA(dgPtr->Content);
        }
    }

    // Or if we just have a pointer...
    auto dgPtr = dynamic_cast<DataGroupPointer*>(dg);
    if(dgPtr != nullptr)
    {
        return this->skipEA(dgPtr->Content);
    }

    return false;
}

std::string PrettyPrinter::GetSymbolToPrint(uint64_t x)
{
    std::stringstream ss;
    ss << ".L_" << std::hex << x << std::dec;
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
