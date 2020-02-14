#include <capstone/capstone.h>
#include <gtest/gtest.h>
#include <gtirb/gtirb.hpp>
#include "../passes/NoReturnPass.h"
#include "../passes/SccPass.h"

gtirb::EdgeLabel simpleFallthrough()
{
    return std::make_tuple(gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect,
                           gtirb::EdgeType::Fallthrough);
}

gtirb::EdgeLabel simpleCall()
{
    return std::make_tuple(gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect,
                           gtirb::EdgeType::Call);
}

gtirb::EdgeLabel simpleReturn()
{
    return std::make_tuple(gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect,
                           gtirb::EdgeType::Return);
}

gtirb::EdgeLabel simpleJump()
{
    return std::make_tuple(gtirb::ConditionalEdge::OnTrue, gtirb::DirectEdge::IsDirect,
                           gtirb::EdgeType::Branch);
}

TEST(Unit_NoRetunPass, remove_simple_fallthrough)
{
    gtirb::Context Ctx;
    auto* M = gtirb::Module::Create(Ctx);
    gtirb::Block* B1 = emplaceBlock(*M, Ctx, gtirb::Addr(0), 1);
    gtirb::Block* B2 = emplaceBlock(*M, Ctx, gtirb::Addr(1), 1);

    auto ExternalBlock = gtirb::ProxyBlock::Create(Ctx);
    auto Symbol = gtirb::emplaceSymbol(*M, Ctx, "exit");
    M->addCfgNode(ExternalBlock);
    gtirb::setReferent(*M, *Symbol, ExternalBlock);

    auto TopBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addCfgNode(TopBlock);

    gtirb::CFG& Cfg = M->getCFG();
    Cfg[*addEdge(B1, B2, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B1, ExternalBlock, Cfg)] = simpleCall();
    Cfg[*addEdge(B2, TopBlock, Cfg)] = simpleReturn();

    computeSCCs(*M);
    std::set<gtirb::Block*> CallNoReturn = NoReturnPass().computeNoReturn(*M, CS_ARCH_X86, CS_MODE_64);

    EXPECT_TRUE(CallNoReturn.count(B1));
    EXPECT_FALSE(CallNoReturn.count(B2));
    EXPECT_EQ(2, Cfg.m_edges.size());
}

TEST(Unit_NoRetunPass, one_path_returns)
{
    /*
    B1 -c> B2 ->B3 -c> Exit
    |      |    |
    |      |    B4 -ret-> B6
    |      B5 -ret-> B6
    B6
    */
    gtirb::Context Ctx;
    auto* M = gtirb::Module::Create(Ctx);
    gtirb::Block* B1 = emplaceBlock(*M, Ctx, gtirb::Addr(1), 1);
    gtirb::Block* B2 = emplaceBlock(*M, Ctx, gtirb::Addr(2), 1);
    gtirb::Block* B3 = emplaceBlock(*M, Ctx, gtirb::Addr(3), 1);
    gtirb::Block* B4 = emplaceBlock(*M, Ctx, gtirb::Addr(4), 1);
    gtirb::Block* B5 = emplaceBlock(*M, Ctx, gtirb::Addr(5), 1);
    gtirb::Block* B6 = emplaceBlock(*M, Ctx, gtirb::Addr(6), 1);

    auto ExitBlock = gtirb::ProxyBlock::Create(Ctx);
    auto Symbol = gtirb::emplaceSymbol(*M, Ctx, "exit");
    M->addCfgNode(ExitBlock);
    gtirb::setReferent(*M, *Symbol, ExitBlock);

    auto TopBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addCfgNode(TopBlock);

    gtirb::CFG& Cfg = M->getCFG();
    Cfg[*addEdge(B1, B6, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B3, B4, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B2, B5, Cfg)] = simpleFallthrough();

    Cfg[*addEdge(B2, B3, Cfg)] = simpleJump();

    Cfg[*addEdge(B1, B2, Cfg)] = simpleCall();
    Cfg[*addEdge(B3, ExitBlock, Cfg)] = simpleCall();

    Cfg[*addEdge(B4, B6, Cfg)] = simpleReturn();
    Cfg[*addEdge(B5, B6, Cfg)] = simpleReturn();
    Cfg[*addEdge(B6, TopBlock, Cfg)] = simpleReturn();

    EXPECT_EQ(9, Cfg.m_edges.size());
    computeSCCs(*M);
    std::set<gtirb::Block*> CallNoReturn = NoReturnPass().computeNoReturn(*M, CS_ARCH_X86, CS_MODE_64);

    EXPECT_TRUE(CallNoReturn.count(B3));
    EXPECT_FALSE(CallNoReturn.count(B1));
    EXPECT_EQ(8, Cfg.m_edges.size());
}

TEST(Unit_NoRetunPass, two_paths_no_return)
{
    /*
    B1 -c> B2 ->B3 -c> Exit
    |      |    |
    |      |    B4 -ret-> B7
    |      B5 -c> Exit
    |      |
    |      B6 -ret -> B7
    B7
    */
    gtirb::Context Ctx;
    auto* M = gtirb::Module::Create(Ctx);
    gtirb::Block* B1 = emplaceBlock(*M, Ctx, gtirb::Addr(1), 1);
    gtirb::Block* B2 = emplaceBlock(*M, Ctx, gtirb::Addr(2), 1);
    gtirb::Block* B3 = emplaceBlock(*M, Ctx, gtirb::Addr(3), 1);
    gtirb::Block* B4 = emplaceBlock(*M, Ctx, gtirb::Addr(4), 1);
    gtirb::Block* B5 = emplaceBlock(*M, Ctx, gtirb::Addr(5), 1);
    gtirb::Block* B6 = emplaceBlock(*M, Ctx, gtirb::Addr(6), 1);
    gtirb::Block* B7 = emplaceBlock(*M, Ctx, gtirb::Addr(7), 1);

    auto ExitBlock = gtirb::ProxyBlock::Create(Ctx);
    auto Symbol = gtirb::emplaceSymbol(*M, Ctx, "exit");
    M->addCfgNode(ExitBlock);
    gtirb::setReferent(*M, *Symbol, ExitBlock);

    auto TopBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addCfgNode(TopBlock);

    gtirb::CFG& Cfg = M->getCFG();
    Cfg[*addEdge(B1, B7, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B3, B4, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B2, B5, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B5, B6, Cfg)] = simpleFallthrough();

    Cfg[*addEdge(B2, B3, Cfg)] = simpleJump();

    Cfg[*addEdge(B1, B2, Cfg)] = simpleCall();
    Cfg[*addEdge(B3, ExitBlock, Cfg)] = simpleCall();
    Cfg[*addEdge(B5, ExitBlock, Cfg)] = simpleCall();

    Cfg[*addEdge(B4, B7, Cfg)] = simpleReturn();
    Cfg[*addEdge(B6, B7, Cfg)] = simpleReturn();
    Cfg[*addEdge(B7, TopBlock, Cfg)] = simpleReturn();

    EXPECT_EQ(11, Cfg.m_edges.size());
    computeSCCs(*M);
    std::set<gtirb::Block*> CallNoReturn = NoReturnPass().computeNoReturn(*M, CS_ARCH_X86, CS_MODE_64);

    EXPECT_TRUE(CallNoReturn.count(B3));
    EXPECT_TRUE(CallNoReturn.count(B5));
    EXPECT_TRUE(CallNoReturn.count(B1));
    EXPECT_EQ(8, Cfg.m_edges.size());
}

TEST(Unit_NoRetunPass, loop_no_return)
{
    /*
    B1 -c> B2
    |      |
    |      B3 -> B2
    |      |
    |      B4 -c> Exit
    |      |
    |      B5 -ret->Top
    B6 -ret->Top
    */
    gtirb::Context Ctx;
    auto* M = gtirb::Module::Create(Ctx);
    gtirb::Block* B1 = emplaceBlock(*M, Ctx, gtirb::Addr(1), 1);
    gtirb::Block* B2 = emplaceBlock(*M, Ctx, gtirb::Addr(2), 1);
    gtirb::Block* B3 = emplaceBlock(*M, Ctx, gtirb::Addr(3), 1);
    gtirb::Block* B4 = emplaceBlock(*M, Ctx, gtirb::Addr(4), 1);
    gtirb::Block* B5 = emplaceBlock(*M, Ctx, gtirb::Addr(5), 1);
    gtirb::Block* B6 = emplaceBlock(*M, Ctx, gtirb::Addr(6), 1);

    auto ExitBlock = gtirb::ProxyBlock::Create(Ctx);
    auto Symbol = gtirb::emplaceSymbol(*M, Ctx, "exit");
    M->addCfgNode(ExitBlock);
    gtirb::setReferent(*M, *Symbol, ExitBlock);

    auto TopBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addCfgNode(TopBlock);

    gtirb::CFG& Cfg = M->getCFG();
    Cfg[*addEdge(B1, B6, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B2, B3, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B3, B4, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B4, B5, Cfg)] = simpleFallthrough();

    Cfg[*addEdge(B3, B2, Cfg)] = simpleJump();

    Cfg[*addEdge(B1, B2, Cfg)] = simpleCall();
    Cfg[*addEdge(B4, ExitBlock, Cfg)] = simpleCall();

    Cfg[*addEdge(B5, TopBlock, Cfg)] = simpleReturn();
    Cfg[*addEdge(B6, TopBlock, Cfg)] = simpleReturn();

    EXPECT_EQ(9, Cfg.m_edges.size());
    computeSCCs(*M);
    std::set<gtirb::Block*> CallNoReturn = NoReturnPass().computeNoReturn(*M, CS_ARCH_X86, CS_MODE_64);

    EXPECT_TRUE(CallNoReturn.count(B4));
    EXPECT_TRUE(CallNoReturn.count(B1));
    EXPECT_EQ(7, Cfg.m_edges.size());
}
