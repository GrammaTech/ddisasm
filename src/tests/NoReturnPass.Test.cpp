#include <gtest/gtest.h>

#include <boost/graph/adjacency_list.hpp>
#include <gtirb/gtirb.hpp>

#include "../AnalysisPipeline.h"
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

static bool edgeIn(const gtirb::CFG& Cfg, const gtirb::CfgNode* FromVertex,
                   const gtirb::CfgNode* ToVertex)
{
    const auto& IdTable = Cfg[boost::graph_bundle];
    if(auto it = IdTable.find(FromVertex); it != IdTable.end())
    {
        auto From = it->second;
        if(it = IdTable.find(ToVertex); it != IdTable.end())
        {
            auto To = it->second;
            return edge(From, To, Cfg).second;
        }
    }

    // One of the nodes isn't in the CFG
    return false;
}

TEST(Unit_NoReturnPass, remove_simple_fallthrough)
{
    gtirb::Context Ctx;
    gtirb::IR* IR = gtirb::IR::Create(Ctx);
    gtirb::Module* M = IR->addModule(Ctx, "test");
    gtirb::Section* S = M->addSection(Ctx, "");
    gtirb::ByteInterval* I = S->addByteInterval(Ctx, gtirb::Addr(0), 2);

    gtirb::CodeBlock* B1 = I->addBlock<gtirb::CodeBlock>(Ctx, 0, 1);
    gtirb::CodeBlock* B2 = I->addBlock<gtirb::CodeBlock>(Ctx, 1, 1);

    auto ExternalBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addProxyBlock(ExternalBlock);

    auto Symbol = M->addSymbol(Ctx, "exit");
    Symbol->setReferent(ExternalBlock);

    auto TopBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addProxyBlock(TopBlock);

    gtirb::CFG& Cfg = M->getIR()->getCFG();

    Cfg[*addEdge(B1, B2, Cfg)] = simpleFallthrough();
    Cfg[*addEdge(B1, ExternalBlock, Cfg)] = simpleCall();
    Cfg[*addEdge(B2, TopBlock, Cfg)] = simpleReturn();

    AnalysisPipeline Pipeline;
    Pipeline.push<SccPass>();
    Pipeline.push<NoReturnPass>();
    Pipeline.run(Ctx, *M);

    // B1, which does not return, should not fall through.
    EXPECT_FALSE(edgeIn(Cfg, B1, B2));

    // The return should be unaffected.
    EXPECT_TRUE(edgeIn(Cfg, B2, TopBlock));

    EXPECT_EQ(2, Cfg.m_edges.size());
}

TEST(Unit_NoReturnPass, one_path_returns)
{
    /*
    B1 -c> B2 ->B3 -c> Exit
    |      |    |
    |      |    B4 -ret-> B6
    |      B5 -ret-> B6
    B6
    */
    gtirb::Context Ctx;
    gtirb::IR* IR = gtirb::IR::Create(Ctx);
    gtirb::Module* M = IR->addModule(Ctx, "test");
    gtirb::Section* S = M->addSection(Ctx, "");
    gtirb::ByteInterval* I = S->addByteInterval(Ctx, gtirb::Addr(0), 7);

    gtirb::CodeBlock* B1 = I->addBlock<gtirb::CodeBlock>(Ctx, 1, 1);
    gtirb::CodeBlock* B2 = I->addBlock<gtirb::CodeBlock>(Ctx, 2, 1);
    gtirb::CodeBlock* B3 = I->addBlock<gtirb::CodeBlock>(Ctx, 3, 1);
    gtirb::CodeBlock* B4 = I->addBlock<gtirb::CodeBlock>(Ctx, 4, 1);
    gtirb::CodeBlock* B5 = I->addBlock<gtirb::CodeBlock>(Ctx, 5, 1);
    gtirb::CodeBlock* B6 = I->addBlock<gtirb::CodeBlock>(Ctx, 6, 1);

    auto ExitBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addProxyBlock(ExitBlock);

    auto Symbol = M->addSymbol(Ctx, "exit");
    Symbol->setReferent(ExitBlock);

    auto TopBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addProxyBlock(TopBlock);

    gtirb::CFG& Cfg = M->getIR()->getCFG();
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

    AnalysisPipeline Pipeline;
    Pipeline.push<SccPass>();
    Pipeline.push<NoReturnPass>();
    Pipeline.run(Ctx, *M);

    // B3, which does not return, should not fall through.
    EXPECT_FALSE(edgeIn(Cfg, B3, B4));

    // B1 is not noreturn, and should still fall through.
    EXPECT_TRUE(edgeIn(Cfg, B1, B6));

    EXPECT_EQ(8, Cfg.m_edges.size());
}

TEST(Unit_NoReturnPass, two_paths_no_return)
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
    gtirb::IR* IR = gtirb::IR::Create(Ctx);
    gtirb::Module* M = IR->addModule(Ctx, "test");
    gtirb::Section* S = M->addSection(Ctx, "");
    gtirb::ByteInterval* I = S->addByteInterval(Ctx, gtirb::Addr(0), 8);

    gtirb::CodeBlock* B1 = I->addBlock<gtirb::CodeBlock>(Ctx, 1, 1);
    gtirb::CodeBlock* B2 = I->addBlock<gtirb::CodeBlock>(Ctx, 2, 1);
    gtirb::CodeBlock* B3 = I->addBlock<gtirb::CodeBlock>(Ctx, 3, 1);
    gtirb::CodeBlock* B4 = I->addBlock<gtirb::CodeBlock>(Ctx, 4, 1);
    gtirb::CodeBlock* B5 = I->addBlock<gtirb::CodeBlock>(Ctx, 5, 1);
    gtirb::CodeBlock* B6 = I->addBlock<gtirb::CodeBlock>(Ctx, 6, 1);
    gtirb::CodeBlock* B7 = I->addBlock<gtirb::CodeBlock>(Ctx, 7, 1);

    auto ExitBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addProxyBlock(ExitBlock);

    auto Symbol = M->addSymbol(Ctx, "exit");
    Symbol->setReferent(ExitBlock);

    auto TopBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addProxyBlock(TopBlock);

    gtirb::CFG& Cfg = M->getIR()->getCFG();

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

    AnalysisPipeline Pipeline;
    Pipeline.push<SccPass>();
    Pipeline.push<NoReturnPass>();
    Pipeline.run(Ctx, *M);

    // No-return blocks should not fallthrough
    EXPECT_FALSE(edgeIn(Cfg, B3, B4));
    EXPECT_FALSE(edgeIn(Cfg, B5, B6));
    EXPECT_FALSE(edgeIn(Cfg, B1, B7));

    EXPECT_EQ(8, Cfg.m_edges.size());
}

TEST(Unit_NoReturnPass, loop_no_return)
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
    gtirb::IR* IR = gtirb::IR::Create(Ctx);
    gtirb::Module* M = IR->addModule(Ctx, "test");
    gtirb::Section* S = M->addSection(Ctx, "");
    gtirb::ByteInterval* I = S->addByteInterval(Ctx, gtirb::Addr(0), 7);

    gtirb::CodeBlock* B1 = I->addBlock<gtirb::CodeBlock>(Ctx, 1, 1);
    gtirb::CodeBlock* B2 = I->addBlock<gtirb::CodeBlock>(Ctx, 2, 1);
    gtirb::CodeBlock* B3 = I->addBlock<gtirb::CodeBlock>(Ctx, 3, 1);
    gtirb::CodeBlock* B4 = I->addBlock<gtirb::CodeBlock>(Ctx, 4, 1);
    gtirb::CodeBlock* B5 = I->addBlock<gtirb::CodeBlock>(Ctx, 5, 1);
    gtirb::CodeBlock* B6 = I->addBlock<gtirb::CodeBlock>(Ctx, 6, 1);

    auto ExitBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addProxyBlock(ExitBlock);

    auto Symbol = M->addSymbol(Ctx, "exit");
    Symbol->setReferent(ExitBlock);

    auto TopBlock = gtirb::ProxyBlock::Create(Ctx);
    M->addProxyBlock(TopBlock);

    gtirb::CFG& Cfg = M->getIR()->getCFG();

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

    AnalysisPipeline Pipeline;
    Pipeline.push<SccPass>();
    Pipeline.push<NoReturnPass>();
    Pipeline.run(Ctx, *M);

    // No-return blocks should not fallthough.
    EXPECT_FALSE(edgeIn(Cfg, B4, B5));
    EXPECT_FALSE(edgeIn(Cfg, B1, B6));

    EXPECT_EQ(7, Cfg.m_edges.size());
}
