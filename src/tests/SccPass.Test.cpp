

#include <gtest/gtest.h>
#include <gtirb/gtirb.hpp>
#include "../passes/SccPass.h"

// TODO
// TEST(Unit_SccPass, loop)
// {
//     gtirb::Context Ctx;
//     auto* M = gtirb::Module::Create(Ctx);
//     gtirb::Block* B1 = emplaceBlock(*M, Ctx, gtirb::Addr(0), 1);
//     gtirb::Block* B2 = emplaceBlock(*M, Ctx, gtirb::Addr(1), 1);
//     gtirb::Block* B3 = emplaceBlock(*M, Ctx, gtirb::Addr(3), 1);

//     gtirb::EdgeLabel SimpleFallthrough = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect,
//         gtirb::EdgeType::Fallthrough);
//     gtirb::EdgeLabel SimpleJump = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect, gtirb::EdgeType::Branch);

//     gtirb::CFG& Cfg = M->getCFG();
//     Cfg[*addEdge(B1, B2, Cfg)] = SimpleFallthrough;
//     Cfg[*addEdge(B2, B3, Cfg)] = SimpleFallthrough;
//     Cfg[*addEdge(B3, B2, Cfg)] = SimpleJump;

//     computeSCCs(*M);
//     auto* SccTable = M->getAuxData<SccMap>("SCCs");
//     EXPECT_NE(SccTable->find(B1->getUUID())->second, SccTable->find(B2->getUUID())->second);
//     EXPECT_NE(SccTable->find(B1->getUUID())->second, SccTable->find(B3->getUUID())->second);

//     EXPECT_EQ(SccTable->find(B2->getUUID())->second, SccTable->find(B3->getUUID())->second);
// }

// TEST(Unit_SccPass, recursion)
// {
//     gtirb::Context Ctx;
//     auto* M = gtirb::Module::Create(Ctx);
//     gtirb::Block* B1 = emplaceBlock(*M, Ctx, gtirb::Addr(0), 1);
//     gtirb::Block* B2 = emplaceBlock(*M, Ctx, gtirb::Addr(1), 1);
//     gtirb::Block* B3 = emplaceBlock(*M, Ctx, gtirb::Addr(3), 1);

//     gtirb::EdgeLabel SimpleFallthrough = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect,
//         gtirb::EdgeType::Fallthrough);
//     gtirb::EdgeLabel SimpleCall = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect, gtirb::EdgeType::Call);
//     gtirb::EdgeLabel SimpleReturn = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect, gtirb::EdgeType::Return);

//     gtirb::CFG& Cfg = M->getCFG();
//     Cfg[*addEdge(B1, B2, Cfg)] = SimpleFallthrough;
//     Cfg[*addEdge(B2, B3, Cfg)] = SimpleFallthrough;
//     Cfg[*addEdge(B3, B2, Cfg)] = SimpleCall;
//     Cfg[*addEdge(B2, B1, Cfg)] = SimpleReturn;

//     computeSCCs(*M);
//     auto* SccTable = M->getAuxData<SccMap>("SCCs");
//     // call  and return edges are ignored
//     EXPECT_NE(SccTable->find(B1->getUUID())->second, SccTable->find(B2->getUUID())->second);
//     EXPECT_NE(SccTable->find(B1->getUUID())->second, SccTable->find(B3->getUUID())->second);
//     EXPECT_NE(SccTable->find(B2->getUUID())->second, SccTable->find(B3->getUUID())->second);
// }

// TEST(Unit_SccPass, nested_loop)
// {
//     gtirb::Context Ctx;
//     auto* M = gtirb::Module::Create(Ctx);
//     gtirb::Block* B1 = emplaceBlock(*M, Ctx, gtirb::Addr(0), 1);
//     gtirb::Block* B2 = emplaceBlock(*M, Ctx, gtirb::Addr(1), 1);
//     gtirb::Block* B3 = emplaceBlock(*M, Ctx, gtirb::Addr(3), 1);

//     gtirb::EdgeLabel SimpleJump = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect, gtirb::EdgeType::Branch);

//     gtirb::CFG& Cfg = M->getCFG();
//     Cfg[*addEdge(B1, B2, Cfg)] = SimpleJump;
//     Cfg[*addEdge(B2, B2, Cfg)] = SimpleJump;
//     Cfg[*addEdge(B2, B3, Cfg)] = SimpleJump;
//     Cfg[*addEdge(B3, B1, Cfg)] = SimpleJump;

//     computeSCCs(*M);
//     auto* SccTable = M->getAuxData<SccMap>("SCCs");
//     // call  and return edges are ignored
//     EXPECT_EQ(SccTable->find(B1->getUUID())->second, SccTable->find(B2->getUUID())->second);
//     EXPECT_EQ(SccTable->find(B1->getUUID())->second, SccTable->find(B3->getUUID())->second);
//     EXPECT_EQ(SccTable->find(B2->getUUID())->second, SccTable->find(B3->getUUID())->second);
// }

// TEST(Unit_SccPass, loops_and_call)
// {
//     gtirb::Context Ctx;
//     auto* M = gtirb::Module::Create(Ctx);
//     gtirb::Block* B1 = emplaceBlock(*M, Ctx, gtirb::Addr(0), 1);
//     gtirb::Block* B2 = emplaceBlock(*M, Ctx, gtirb::Addr(1), 1);
//     gtirb::Block* B3 = emplaceBlock(*M, Ctx, gtirb::Addr(3), 1);
//     gtirb::Block* B4 = emplaceBlock(*M, Ctx, gtirb::Addr(3), 1);

//     gtirb::EdgeLabel SimpleFallthrough = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect,
//         gtirb::EdgeType::Fallthrough);
//     gtirb::EdgeLabel SimpleJump = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect, gtirb::EdgeType::Branch);
//     gtirb::EdgeLabel SimpleCall = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect, gtirb::EdgeType::Call);
//     gtirb::EdgeLabel SimpleReturn = std::make_tuple(
//         gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect, gtirb::EdgeType::Return);

//     gtirb::CFG& Cfg = M->getCFG();
//     Cfg[*addEdge(B1, B2, Cfg)] = SimpleFallthrough;
//     Cfg[*addEdge(B2, B1, Cfg)] = SimpleJump;

//     Cfg[*addEdge(B1, B3, Cfg)] = SimpleCall;
//     Cfg[*addEdge(B4, B2, Cfg)] = SimpleReturn;

//     Cfg[*addEdge(B3, B4, Cfg)] = SimpleFallthrough;
//     Cfg[*addEdge(B4, B3, Cfg)] = SimpleJump;

//     computeSCCs(*M);
//     auto* SccTable = M->getAuxData<SccMap>("SCCs");
//     // call  and return edges are ignored
//     EXPECT_EQ(SccTable->find(B1->getUUID())->second, SccTable->find(B2->getUUID())->second);
//     EXPECT_EQ(SccTable->find(B3->getUUID())->second, SccTable->find(B4->getUUID())->second);

//     EXPECT_NE(SccTable->find(B1->getUUID())->second, SccTable->find(B3->getUUID())->second);
//     EXPECT_NE(SccTable->find(B2->getUUID())->second, SccTable->find(B3->getUUID())->second);
//     EXPECT_NE(SccTable->find(B1->getUUID())->second, SccTable->find(B4->getUUID())->second);
//     EXPECT_NE(SccTable->find(B2->getUUID())->second, SccTable->find(B4->getUUID())->second);
// }
