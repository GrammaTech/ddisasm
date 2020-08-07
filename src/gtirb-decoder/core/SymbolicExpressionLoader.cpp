//===- SymbolicExpressionLoader.cpp -----------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
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
#include "SymbolicExpressionLoader.h"

#include "../../AuxDataSchema.h"

void SymbolicExpressionLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<relations::SymbolicExpression> SymbolicExpressions;
    std::vector<relations::SymbolMinusSymbol> SymbolMinusSymbols;

    for(const auto& SymExprElem : Module.symbolic_expressions())
    {
        const gtirb::ByteInterval* Bytes = SymExprElem.getByteInterval();
        const gtirb::SymbolicExpression& SymExpr = SymExprElem.getSymbolicExpression();
        if(std::optional<gtirb::Addr> Addr = Bytes->getAddress(); Addr)
        {
            if(auto* AddrConst = std::get_if<gtirb::SymAddrConst>(&SymExpr))
            {
                std::optional<gtirb::Addr> Symbol = AddrConst->Sym->getAddress();
                if(Symbol)
                {
                    SymbolicExpressions.push_back({*Addr, *Symbol, AddrConst->Offset});
                }
            }
            if(auto* AddrAddr = std::get_if<gtirb::SymAddrAddr>(&SymExpr))
            {
                std::optional<gtirb::Addr> Symbol1 = AddrAddr->Sym1->getAddress();
                std::optional<gtirb::Addr> Symbol2 = AddrAddr->Sym2->getAddress();
                if(Symbol1 && Symbol2)
                {
                    SymbolMinusSymbols.push_back({*Addr, *Symbol1, *Symbol2, AddrAddr->Offset});
                }
            }
        }
    }

    Program.insert("symbolic_expression", std::move(SymbolicExpressions));
    Program.insert("symbol_minus_symbol", std::move(SymbolMinusSymbols));
}

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolicExpression& Expr)
    {
        T << Expr.Address << Expr.Symbol << Expr.Offset;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolMinusSymbol& Expr)
    {
        T << Expr.Address << Expr.Symbol1 << Expr.Symbol2 << Expr.Offset;
        return T;
    }
} // namespace souffle
