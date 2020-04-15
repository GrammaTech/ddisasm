//===- DatalogUtils.cpp -----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#include "DatalogUtils.h"
#include "AuxDataSchema.h"

void writeFacts(souffle::SouffleProgram* prog, const std::string& directory)
{
    std::ios_base::openmode filemask = std::ios::out;
    for(souffle::Relation* relation : prog->getInputRelations())
    {
        std::ofstream file(directory + relation->getName() + ".facts", filemask);
        souffle::SymbolTable symbolTable = relation->getSymbolTable();
        for(souffle::tuple tuple : *relation)
        {
            for(size_t i = 0; i < tuple.size(); i++)
            {
                if(i > 0)
                    file << "\t";
                if(relation->getAttrType(i)[0] == 's')
                    file << symbolTable.resolve(tuple[i]);
                else
                    file << tuple[i];
            }
            file << std::endl;
        }
        file.close();
    }
}

void populateEdgeProperties(souffle::tuple& T, const gtirb::EdgeLabel& Label)
{
    assert(Label.has_value() && "Found edge without a label");
    if(std::get<gtirb::ConditionalEdge>(*Label) == gtirb::ConditionalEdge::OnTrue)
        T << "true";
    else
        T << "false";
    if(std::get<gtirb::DirectEdge>(*Label) == gtirb::DirectEdge::IsIndirect)
        T << "true";
    else
        T << "false";
    switch(std::get<gtirb::EdgeType>(*Label))
    {
        case gtirb::EdgeType::Branch:
            T << "branch";
            break;
        case gtirb::EdgeType::Call:
            T << "call";
            break;
        case gtirb::EdgeType::Fallthrough:
            T << "fallthrough";
            break;
        case gtirb::EdgeType::Return:
            T << "return";
            break;
        case gtirb::EdgeType::Syscall:
            T << "syscall";
            break;
        case gtirb::EdgeType::Sysret:
            T << "sysret";
            break;
    }
}

std::string str_toupper(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<unsigned char>(std::toupper(c)); });
    return s;
}

std::string getRegisterName(const csh& CsHandle, unsigned int reg)
{
    if(reg == X86_REG_INVALID)
        return "NONE";
    std::string name = str_toupper(cs_reg_name(CsHandle, reg));
    return name;
}

std::variant<ImmOp, RegOp, IndirectOp> buildOperand(const csh& CsHandle, const cs_x86_op& op)
{
    switch(op.type)
    {
        case X86_OP_REG:
            return getRegisterName(CsHandle, op.reg);
        case X86_OP_IMM:
            return op.imm;
        case X86_OP_MEM:
        {
            IndirectOp I = {getRegisterName(CsHandle, op.mem.segment),
                            getRegisterName(CsHandle, op.mem.base),
                            getRegisterName(CsHandle, op.mem.index),
                            op.mem.scale,
                            op.mem.disp,
                            op.size * 8};
            return I;
        }
        case X86_OP_INVALID:
        default:
            std::cerr << "invalid operand\n";
            exit(1);
    }
}

DlInstruction GtirbToDatalog::transformInstruction(const csh& CsHandle, DlOperandTable& OpDict,
                                                   const cs_insn& insn)
{
    std::vector<uint64_t> op_codes;
    std::string prefix_name = str_toupper(insn.mnemonic);
    std::string prefix, name;
    size_t pos = prefix_name.find(' ');
    if(pos != std::string::npos)
    {
        prefix = prefix_name.substr(0, pos);
        name = prefix_name.substr(pos + 1);
    }
    else
    {
        prefix = "";
        name = prefix_name;
    }

    auto& detail = insn.detail->x86;
    if(name != "NOP")
    {
        auto opCount = detail.op_count;
        for(int i = 0; i < opCount; i++)
        {
            const auto& op = detail.operands[i];
            uint64_t index = OpDict.add(buildOperand(CsHandle, op));
            op_codes.push_back(index);
        }
        // we put the destination operand at the end
        if(opCount > 0)
            std::rotate(op_codes.begin(), op_codes.begin() + 1, op_codes.end());
    }
    return {insn.address,
            insn.size,
            prefix,
            name,
            op_codes,
            detail.encoding.imm_offset,
            detail.encoding.disp_offset};
}

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& t, const gtirb::Addr& a)
    {
        t << static_cast<uint64_t>(a);
        return t;
    }

    souffle::tuple& operator<<(souffle::tuple& t, const DlInstruction& inst)
    {
        t << inst.address << inst.size << inst.prefix << inst.name;
        for(size_t i = 0; i < 4; ++i)
        {
            if(i < inst.op_codes.size())
                t << inst.op_codes[i];
            else
                t << 0;
        }
        t << inst.immediateOffset << inst.displacementOffset;
        return t;
    }
} // namespace souffle

void GtirbToDatalog::populateBlocks(const gtirb::Module& M)
{
    if(M.code_blocks().empty())
        return;

    auto* BlocksRel = Prog->getRelation("block");
    auto* NextBlockRel = Prog->getRelation("next_block");
    std::optional<gtirb::Addr> PrevBlockAddr = M.code_blocks().begin()->getAddress();

    for(auto& Block : M.code_blocks())
    {
        uint64_t BlockSize = Block.getSize();
        std::optional<gtirb::Addr> BlockAddr = Block.getAddress();

        assert(BlockAddr && PrevBlockAddr && "Found code block without address.");

        souffle::tuple T(BlocksRel);
        T << *BlockAddr << BlockSize;
        BlocksRel->insert(T);

        if(*PrevBlockAddr < *BlockAddr)
        {
            souffle::tuple TupleNext(NextBlockRel);
            TupleNext << *PrevBlockAddr << *BlockAddr;
            NextBlockRel->insert(TupleNext);
        }
        PrevBlockAddr = BlockAddr;
    }
}

void GtirbToDatalog::populateInstructions(const gtirb::Module& M, int InstructionLimit)
{
    csh CsHandle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &CsHandle); // == CS_ERR_OK
    cs_option(CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    // Exception-safe capstone handle closing
    std::unique_ptr<csh, std::function<void(csh*)>> CloseCapstoneHandle(&CsHandle, cs_close);

    std::vector<DlInstruction> Insns;
    DlOperandTable OpDict;
    for(auto& Block : M.code_blocks())
    {
        assert(Block.getAddress() && "Found code block without address.");

        cs_insn* Insn;
        const gtirb::ByteInterval* Bytes = Block.getByteInterval();
        uint64_t InitSize = Bytes->getInitializedSize();
        assert(Bytes->getSize() == InitSize && "Found partially initialized code block.");
        size_t Count =
            cs_disasm(CsHandle, Bytes->rawBytes<uint8_t>(), InitSize,
                      static_cast<uint64_t>(*Block.getAddress()), InstructionLimit, &Insn);

        // Exception-safe cleanup of instructions
        std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> freeInsn(
            Insn, [Count](cs_insn* i) { cs_free(i, Count); });
        for(size_t i = 0; i < Count; ++i)
        {
            Insns.push_back(GtirbToDatalog::transformInstruction(CsHandle, OpDict, Insn[i]));
        }
    }
    GtirbToDatalog::addToRelation(&*Prog, "instruction", Insns);
    GtirbToDatalog::addToRelation(&*Prog, "op_regdirect", OpDict.regTable);
    GtirbToDatalog::addToRelation(&*Prog, "op_immediate", OpDict.immTable);
    GtirbToDatalog::addToRelation(&*Prog, "op_indirect", OpDict.indirectTable);
}

void GtirbToDatalog::populateCfgEdges(const gtirb::Module& M)
{
    std::map<const gtirb::ProxyBlock*, std::string> InvSymbolMap;
    for(auto& Symbol : M.symbols())
    {
        if(const gtirb::ProxyBlock* Proxy = Symbol.getReferent<gtirb::ProxyBlock>())
            InvSymbolMap[Proxy] = Symbol.getName();
    }
    const gtirb::CFG& Cfg = M.getIR()->getCFG();
    auto* EdgeRel = Prog->getRelation("cfg_edge");
    auto* TopEdgeRel = Prog->getRelation("cfg_edge_to_top");
    auto* SymbolEdgeRel = Prog->getRelation("cfg_edge_to_symbol");
    for(auto& Edge : Cfg.m_edges)
    {
        if(const gtirb::CodeBlock* Src = dyn_cast<gtirb::CodeBlock>(Cfg[Edge.m_source]))
        {
            std::optional<gtirb::Addr> SrcAddr = Src->getAddress();
            assert(SrcAddr && "Found source block without address.");

            if(const gtirb::CodeBlock* Dest = dyn_cast<gtirb::CodeBlock>(Cfg[Edge.m_target]))
            {
                std::optional<gtirb::Addr> DestAddr = Dest->getAddress();
                assert(DestAddr && "Found destination block without address.");

                souffle::tuple T(EdgeRel);
                T << *SrcAddr << *DestAddr;
                populateEdgeProperties(T, Edge.get_property());
                EdgeRel->insert(T);
            }

            if(const gtirb::ProxyBlock* Dest = dyn_cast<gtirb::ProxyBlock>(Cfg[Edge.m_target]))
            {
                auto foundSymbol = InvSymbolMap.find(Dest);
                if(foundSymbol != InvSymbolMap.end())
                {
                    souffle::tuple T(SymbolEdgeRel);
                    T << *SrcAddr << foundSymbol->second;
                    populateEdgeProperties(T, Edge.get_property());
                    SymbolEdgeRel->insert(T);
                }
                else
                {
                    souffle::tuple T(TopEdgeRel);
                    T << *SrcAddr;
                    populateEdgeProperties(T, Edge.get_property());
                    TopEdgeRel->insert(T);
                }
            }
        }
    }
}

void GtirbToDatalog::populateSccs(gtirb::Module& M)
{
    auto* InSccRel = Prog->getRelation("in_scc");
    auto* SccTable = M.getAuxData<gtirb::schema::Sccs>();
    assert(SccTable && "SCCs AuxData table missing from GTIRB module");
    std::vector<int> SccBlockIndex;
    for(auto& Block : M.code_blocks())
    {
        assert(Block.getAddress() && "Found code block without address.");
        auto Found = SccTable->find(Block.getUUID());
        assert(Found != SccTable->end() && "Block missing from SCCs table");
        uint64_t SccIndex = Found->second;
        if(SccBlockIndex.size() <= SccIndex)
            SccBlockIndex.resize(SccIndex + 1);
        souffle::tuple T(InSccRel);
        T << SccIndex << SccBlockIndex[SccIndex]++ << *Block.getAddress();
        InSccRel->insert(T);
    }
}

void GtirbToDatalog::populateSymbolicExpressions(const gtirb::Module& M)
{
    auto* SymExprRel = Prog->getRelation("symbolic_expression");
    auto* SymMinusSymRel = Prog->getRelation("symbol_minus_symbol");
    for(const auto& SymExprElem : M.symbolic_expressions())
    {
        const gtirb::ByteInterval* Bytes = SymExprElem.getByteInterval();
        const gtirb::SymbolicExpression& SymExpr = SymExprElem.getSymbolicExpression();
        if(std::optional<gtirb::Addr> Addr = Bytes->getAddress(); Addr)
        {
            if(auto* AddrConst = std::get_if<gtirb::SymAddrConst>(&SymExpr))
            {
                if(AddrConst->Sym->getAddress())
                {
                    souffle::tuple T(SymExprRel);
                    T << *Addr << *(AddrConst->Sym->getAddress()) << AddrConst->Offset;
                    SymExprRel->insert(T);
                }
            }
            if(auto* AddrAddr = std::get_if<gtirb::SymAddrAddr>(&SymExpr))
            {
                if(AddrAddr->Sym1->getAddress() && AddrAddr->Sym2->getAddress())
                {
                    souffle::tuple T(SymMinusSymRel);
                    T << *Addr << *(AddrAddr->Sym1->getAddress()) << *(AddrAddr->Sym2->getAddress())
                      << AddrAddr->Offset;
                    SymMinusSymRel->insert(T);
                }
            }
        }
    }
}

void GtirbToDatalog::populateFdeEntries(const gtirb::Context& Ctx, gtirb::Module& M)
{
    std::set<gtirb::Addr> FdeStart;
    std::set<gtirb::Addr> FdeEnd;
    auto* CfiDirectives = M.getAuxData<gtirb::schema::CfiDirectives>();
    if(!CfiDirectives)
        return;
    for(auto& Pair : *CfiDirectives)
    {
        auto* Block =
            dyn_cast<const gtirb::CodeBlock>(gtirb::Node::getByUUID(Ctx, Pair.first.ElementId));
        assert(Block && "Found CFI directive that does not belong to a block");

        std::optional<gtirb::Addr> BlockAddr = Block->getAddress();
        assert(BlockAddr && "Found code block without address.");

        for(auto& Directive : Pair.second)
        {
            if(std::get<0>(Directive) == ".cfi_startproc")
                FdeStart.insert(*BlockAddr + Pair.first.Displacement);
            if(std::get<0>(Directive) == ".cfi_endproc")
                FdeEnd.insert(*BlockAddr + Pair.first.Displacement);
        }
    }
    assert(FdeStart.size() == FdeEnd.size() && "Malformed CFI directives");
    auto StartIt = FdeStart.begin();
    auto EndIt = FdeEnd.begin();
    auto* FdeAddresses = Prog->getRelation("fde_addresses");
    for(; StartIt != FdeStart.end(); ++StartIt, ++EndIt)
    {
        souffle::tuple T(FdeAddresses);
        T << *StartIt << *EndIt;
        FdeAddresses->insert(T);
    }
}

void GtirbToDatalog::populateFunctionEntries(const gtirb::Context& Ctx, gtirb::Module& M)
{
    auto* FunctionEntries = M.getAuxData<gtirb::schema::FunctionEntries>();
    if(!FunctionEntries)
        return;
    auto* FunctionEntryRel = Prog->getRelation("function_entry");
    for(auto& Pair : *FunctionEntries)
    {
        for(auto& UUID : Pair.second)
        {
            if(auto* Block = dyn_cast<gtirb::CodeBlock>(gtirb::Node::getByUUID(Ctx, UUID)))
            {
                assert(Block->getAddress() && "Found code block without address.");
                souffle::tuple T(FunctionEntryRel);
                T << *Block->getAddress();
                FunctionEntryRel->insert(T);
            }
        }
    }
}

void GtirbToDatalog::populatePadding(const gtirb::Context& Ctx, gtirb::Module& M)
{
    auto* Padding = M.getAuxData<gtirb::schema::Padding>();
    if(!Padding)
        return;
    auto* PaddingRel = Prog->getRelation("padding");
    for(auto& [Offset, Size] : *Padding)
    {
        souffle::tuple T(PaddingRel);
        auto* ByteInterval =
            dyn_cast_or_null<gtirb::ByteInterval>(gtirb::Node::getByUUID(Ctx, Offset.ElementId));
        assert(ByteInterval && "Failed to find ByteInterval by UUID.");
        if(ByteInterval->getAddress())
        {
            gtirb::Addr Addr = *ByteInterval->getAddress() + Offset.Displacement;
            T << Addr << Size;
            PaddingRel->insert(T);
        }
    }
}
