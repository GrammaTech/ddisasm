#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <gtirb/gtirb.hpp>

#include "../AuxDataSchema.h"
#include "../Registration.h"
#include "../gtirb-decoder/DatalogProgram.h"

namespace fs = boost::filesystem;

struct GTIRB
{
    std::unique_ptr<gtirb::Context> Context;
    gtirb::IR *IR;
    gtirb::Module *Module;
};

GTIRB buildGtirb(gtirb::ISA ISA, std::vector<uint8_t> &Bytes)
{
    registerDatalogLoaders();

    auto Context = std::make_unique<gtirb::Context>();
    gtirb::IR *IR = gtirb::IR::Create(*Context);
    gtirb::Module *Module = gtirb::Module::Create(*Context, "TestModule");
    IR->addModule(Module);

    Module->setFileFormat(gtirb::FileFormat::ELF);
    Module->setISA(ISA);
    Module->setByteOrder(gtirb::ByteOrder::Little);

    std::vector<std::string> BinaryType;
    BinaryType.emplace_back("EXEC");
    Module->addAuxData<gtirb::schema::BinaryType>(std::move(BinaryType));

    uint64_t Addr = 0x10000;

    gtirb::Section *S = Module->addSection(*Context, ".text");
    S->addByteInterval(*Context, gtirb::Addr(Addr), Bytes.begin(), Bytes.end(), Bytes.size(),
                       Bytes.size());
    S->addFlag(gtirb::SectionFlag::Loaded);
    S->addFlag(gtirb::SectionFlag::Readable);
    S->addFlag(gtirb::SectionFlag::Executable);
    S->addFlag(gtirb::SectionFlag::Initialized);

    std::map<uint64_t, gtirb::UUID> SectionIndex;
    std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> SectionProperties;
    std::map<gtirb::UUID, uint64_t> Alignment;

    SectionIndex[0] = S->getUUID();
    SectionProperties[S->getUUID()] = {
        static_cast<uint64_t>(1 /* SHT_PROGBITS */),
        static_cast<uint64_t>(4 | 2 /* SHF_EXECINSTR | SHF_ALLOC */)};
    Alignment[S->getUUID()] = 8;

    Module->addAuxData<gtirb::schema::Alignment>(std::move(Alignment));
    Module->addAuxData<gtirb::schema::SectionIndex>(std::move(SectionIndex));
    Module->addAuxData<gtirb::schema::SectionTypeFlags>(std::move(SectionProperties));

    return GTIRB{std::move(Context), IR, Module};
}

std::optional<DatalogProgram> runSouffle(GTIRB &Gtirb)
{
    std::optional<DatalogProgram> Souffle = DatalogProgram::load(*Gtirb.Module);
    if(!Souffle)
    {
        return std::nullopt;
    }

    auto DebugDir = fs::temp_directory_path() / fs::unique_path();
    std::cout << "\t\tWriting relations to " << DebugDir << "\n";
    fs::create_directories(DebugDir);
    std::string DebugDirPath(DebugDir.string() + "/");

    Souffle->writeFacts(DebugDirPath);
    Souffle->run();
    Souffle->writeRelations(DebugDirPath);
    return Souffle;
}

struct MemoryAccess
{
    std::string Type;
    uint64_t Addr;
    uint64_t SrcOp;
    uint64_t DstOp;
    std::string DirectReg;
    std::string BaseReg;
    std::string IndexReg;
    int64_t Mult;
    int64_t Offset;

    bool operator==(const MemoryAccess &other) const
    {
        return this->Type == other.Type && this->Addr == other.Addr && this->SrcOp == other.SrcOp
               && this->DstOp == other.DstOp && this->DirectReg == other.DirectReg
               && this->BaseReg == other.BaseReg && this->IndexReg == other.IndexReg
               && this->Mult == other.Mult && this->Offset == other.Offset;
    }
};

std::ostream &operator<<(std::ostream &Stream, MemoryAccess const &ma)
{
    Stream << ma.Type << " " << std::hex << ma.Addr << std::dec << " " << ma.SrcOp << " "
           << ma.DstOp << " " << ma.DirectReg << " " << ma.BaseReg << " " << ma.IndexReg << " "
           << ma.Mult << " " << ma.Offset;
    return Stream;
}

class Hash
{
public:
    size_t operator()(const MemoryAccess &access) const
    {
        return std::hash<int64_t>()(access.Addr);
    }
};

TEST(ArchMemoryAccessRelation, Arm64)
{
    std::unordered_set<MemoryAccess, Hash> ExpectedMemoryAccesses = {
        {"LOAD", 0x10000, 1, 2, "X0", "X1", "NONE", 0, 16},
        {"STORE", 0x10004, 2, 1, "X0", "X1", "NONE", 0, 16},
        {"LOAD", 0x10008, 1, 2, "X0", "X1", "NONE", 0, 16},
        {"STORE", 0x1000C, 2, 1, "X0", "X1", "NONE", 0, 16},
        {"LOAD", 0x10010, 1, 3, "X0", "X1", "NONE", 0, 0},
        {"STORE", 0x10014, 3, 1, "X0", "X1", "NONE", 0, 0},
        {"LOAD", 0x10018, 1, 2, "X0", "NONE", "NONE", 0, 0x10018 + 16},
        {"LOAD", 0x1001C, 1, 2, "W0", "X1", "W2", 4, 0},
        {"LOAD", 0x10020, 1, 2, "X0", "X1", "W2", 8, 0},
        {"LOAD", 0x10024, 1, 2, "W0", "X1", "X2", 4, 0},
        {"LOAD", 0x10028, 1, 2, "X0", "X1", "X2", 8, 0},
        {"LOAD", 0x1002C, 1, 2, "W0", "X1", "W2", 4, 0},
        {"LOAD", 0x10030, 1, 2, "X0", "X1", "W2", 8, 0},
        {"LOAD", 0x10034, 1, 2, "W0", "X1", "X2", 4, 0},
        {"LOAD", 0x10038, 1, 2, "X0", "X1", "X2", 8, 0},
        {"STORE", 0x1003C, 2, 1, "X0", "X1", "X2", 8, 0},
        {"LOAD", 0x10040, 2, 1, "X0", "X2", "NONE", 0, 16},
        {"LOAD", 0x10040, 2, 3, "X1", "X2", "NONE", 0, 24},
        {"STORE", 0x10044, 1, 2, "X0", "X2", "NONE", 0, 16},
        {"STORE", 0x10044, 3, 2, "X1", "X2", "NONE", 0, 24},
        {"LOAD", 0x10048, 2, 1, "W0", "X2", "NONE", 0, 16},
        {"LOAD", 0x10048, 2, 3, "W1", "X2", "NONE", 0, 20},
        {"LOAD", 0x1004C, 2, 1, "X0", "X2", "NONE", 0, 16},
        {"LOAD", 0x1004C, 2, 3, "X1", "X2", "NONE", 0, 24},
        {"STORE", 0x10050, 1, 2, "X0", "X2", "NONE", 0, 16},
        {"STORE", 0x10050, 3, 2, "X1", "X2", "NONE", 0, 24},
        {"LOAD", 0x10054, 2, 1, "W0", "X2", "NONE", 0, 16},
        {"LOAD", 0x10054, 2, 3, "W1", "X2", "NONE", 0, 20},
        {"LOAD", 0x10058, 2, 1, "X0", "X2", "NONE", 0, 0},
        {"LOAD", 0x10058, 2, 4, "X1", "X2", "NONE", 0, 8},
        {"STORE", 0x1005C, 1, 2, "X0", "X2", "NONE", 0, 0},
        {"STORE", 0x1005C, 4, 2, "X1", "X2", "NONE", 0, 8},
        {"LOAD", 0x10060, 2, 1, "W0", "X2", "NONE", 0, 0},
        {"LOAD", 0x10060, 2, 4, "W1", "X2", "NONE", 0, 4},
    };

    std::vector<uint8_t> Bytes = {
        0x20, 0x08, 0x40, 0xF9, // 0x10000: ldr x0, [x1, #16]
        0x20, 0x08, 0x00, 0xF9, // 0x10004: str x0, [x1, #16]
        0x20, 0x0C, 0x41, 0xF8, // 0x10008: ldr x0, [x1, #16]!
        0x20, 0x0C, 0x01, 0xF8, // 0x1000C: str x0, [x1, #16]!
        0x20, 0x04, 0x41, 0xF8, // 0x10010: ldr x0, [x1], #16
        0x20, 0x04, 0x01, 0xF8, // 0x10014: str x0, [x1], #16
        0x80, 0x00, 0x00, 0x58, // 0x10018: ldr x0, #16
        0x20, 0x58, 0x62, 0xB8, // 0x1001C: ldr w0, [x1, w2, uxtw #2]
        0x20, 0x58, 0x62, 0xF8, // 0x10020: ldr x0, [x1, w2, uxtw #3]
        0x20, 0x78, 0x62, 0xB8, // 0x10024: ldr w0, [x1, x2, lsl #2]
        0x20, 0x78, 0x62, 0xF8, // 0x10028: ldr x0, [x1, x2, lsl #3]
        0x20, 0xD8, 0x62, 0xB8, // 0x1002C: ldr w0, [x1, w2, sxtw #2]
        0x20, 0xD8, 0x62, 0xF8, // 0x10030: ldr x0, [x1, w2, sxtw #3]
        0x20, 0xF8, 0x62, 0xB8, // 0x10034: ldr w0, [x1, x2, sxtx #2]
        0x20, 0xF8, 0x62, 0xF8, // 0x10038: ldr x0, [x1, x2, sxtx #3]
        0x20, 0x78, 0x22, 0xF8, // 0x1003C: str x0, [x1, x2, lsl #3]
        0x40, 0x04, 0x41, 0xA9, // 0x10040: ldp x0, x1, [x2, #16]
        0x40, 0x04, 0x01, 0xA9, // 0x10044: stp x0, x1, [x2, #16]
        0x40, 0x04, 0x42, 0x29, // 0x10048: ldp w0, w1, [x2, #16]
        0x40, 0x04, 0xC1, 0xA9, // 0x1004C: ldp x0, x1, [x2, #16]!
        0x40, 0x04, 0x81, 0xA9, // 0x10050: stp x0, x1, [x2, #16]!
        0x40, 0x04, 0xC2, 0x29, // 0x10054: ldp w0, w1, [x2, #16]!
        0x40, 0x04, 0xC1, 0xA8, // 0x10058: ldp x0, x1, [x2], #16
        0x40, 0x04, 0x81, 0xA8, // 0x1005C: stp x0, x1, [x2], #16
        0x40, 0x04, 0xC2, 0x28, // 0x10060: ldp w0, w1, [x2], #16
        0xC0, 0x03, 0x5F, 0xD6  // ret - satisfy code/data inference.
    };
    GTIRB Gtirb = buildGtirb(gtirb::ISA::ARM64, Bytes);

    auto Souffle = runSouffle(Gtirb);
    if(!Souffle)
        FAIL();

    souffle::SouffleProgram *Prog = Souffle->get();

    unsigned int Count = 0;
    for(auto &output : *Prog->getRelation("arch.memory_access"))
    {
        MemoryAccess Result;

        // Load relation
        output >> Result.Type >> Result.Addr >> Result.SrcOp >> Result.DstOp >> Result.DirectReg
            >> Result.BaseReg >> Result.IndexReg >> Result.Mult >> Result.Offset;

        SCOPED_TRACE(Result);

        // Verify - is it expected?
        auto It = ExpectedMemoryAccesses.find(Result);
        EXPECT_FALSE(It == ExpectedMemoryAccesses.end());
        Count++;
    };

    EXPECT_EQ(Count, ExpectedMemoryAccesses.size());
}

TEST(ArchMemoryAccessRelation, Arm32)
{
    std::unordered_set<MemoryAccess, Hash> ExpectedMemoryAccesses = {
        {"LOAD", 0x10000, 1, 2, "R0", "R1", "NONE", 0, 16},
        {"STORE", 0x10004, 2, 1, "R0", "R1", "NONE", 0, 16},
        {"LOAD", 0x10008, 1, 2, "R0", "R1", "NONE", 0, 16},
        {"STORE", 0x1000C, 2, 1, "R0", "R1", "NONE", 0, 16},
        {"LOAD", 0x10010, 1, 3, "R0", "R1", "NONE", 0, 0},
        {"STORE", 0x10014, 3, 1, "R0", "R1", "NONE", 0, 0},
        {"LOAD", 0x10018, 1, 2, "R0", "R1", "R2", 4, 0},
        {"STORE", 0x1001C, 2, 1, "R0", "R1", "R2", 4, 0},
        {"LOAD", 0x10020, 1, 2, "R0", "R1", "R2", 4, 0},
        {"STORE", 0x10024, 2, 1, "R0", "R1", "R2", 4, 0},
        {"LOAD", 0x10028, 1, 3, "R0", "R1", "NONE", 0, 0},
        {"STORE", 0x1002C, 3, 1, "R0", "R1", "NONE", 0, 0},
        {"LOAD", 0x10030, 2, 3, "R0", "R2", "NONE", 0, 16},
        {"LOAD", 0x10030, 2, 1, "R1", "R2", "NONE", 0, 20},
        {"STORE", 0x10034, 3, 2, "R0", "R2", "NONE", 0, 16},
        {"STORE", 0x10034, 1, 2, "R1", "R2", "NONE", 0, 20},
        {"LOAD", 0x10038, 2, 3, "R0", "R2", "NONE", 0, 16},
        {"LOAD", 0x10038, 2, 1, "R1", "R2", "NONE", 0, 20},
        {"STORE", 0x1003C, 3, 2, "R0", "R2", "NONE", 0, 16},
        {"STORE", 0x1003C, 1, 2, "R1", "R2", "NONE", 0, 20},
        {"LOAD", 0x10040, 2, 4, "R0", "R2", "NONE", 0, 0},
        {"LOAD", 0x10040, 2, 1, "R1", "R2", "NONE", 0, 4},
        {"STORE", 0x10044, 4, 2, "R0", "R2", "NONE", 0, 0},
        {"STORE", 0x10044, 1, 2, "R1", "R2", "NONE", 0, 4},
        {"LOAD", 0x10048, 2, 3, "R0", "R2", "R3", 1, 0},
        {"LOAD", 0x10048, 2, 1, "R1", "R2", "R3", 1, 4},
        {"STORE", 0x1004C, 3, 2, "R0", "R2", "R3", 1, 0},
        {"STORE", 0x1004C, 1, 2, "R1", "R2", "R3", 1, 4},
        {"LOAD", 0x10050, 2, 3, "R0", "R2", "R3", 1, 0},
        {"LOAD", 0x10050, 2, 1, "R1", "R2", "R3", 1, 4},
        {"STORE", 0x10054, 3, 2, "R0", "R2", "R3", 1, 0},
        {"STORE", 0x10054, 1, 2, "R1", "R2", "R3", 1, 4},
        {"LOAD", 0x10058, 2, 4, "R0", "R2", "NONE", 0, 0},
        {"LOAD", 0x10058, 2, 1, "R1", "R2", "NONE", 0, 4},
        {"STORE", 0x1005C, 4, 2, "R0", "R2", "NONE", 0, 0},
        {"STORE", 0x1005C, 1, 2, "R1", "R2", "NONE", 0, 4},
    };

    std::vector<uint8_t> Bytes = {
        0x10, 0x00, 0x91, 0xE5, // 0x10000: ldr r0, [r1, #16]
        0x10, 0x00, 0x81, 0xE5, // 0x10004: str r0, [r1, #16]
        0x10, 0x00, 0xB1, 0xE5, // 0x10008: ldr r0, [r1, #16]!
        0x10, 0x00, 0xA1, 0xE5, // 0x1000C: str r0, [r1, #16]!
        0x10, 0x00, 0x91, 0xE4, // 0x10010: ldr r0, [r1], #16
        0x10, 0x00, 0x81, 0xE4, // 0x10014: str r0, [r1], #16
        0x02, 0x01, 0x91, 0xE7, // 0x10018: ldr r0, [r1, r2, lsl #2]
        0x02, 0x01, 0x81, 0xE7, // 0x1001C: str r0, [r1, r2, lsl #2]
        0x02, 0x01, 0xB1, 0xE7, // 0x10020: ldr r0, [r1, r2, lsl #2]!
        0x02, 0x01, 0xA1, 0xE7, // 0x10024: str r0, [r1, r2, lsl #2]!
        0x02, 0x01, 0x91, 0xE6, // 0x10028: ldr r0, [r1], r2, lsl #2
        0x02, 0x01, 0x81, 0xE6, // 0x1002C: str r0, [r1], r2, lsl #2
        0xD0, 0x01, 0xC2, 0xE1, // 0x10030: ldrd r0, [r2, #16]
        0xF0, 0x01, 0xC2, 0xE1, // 0x10034: strd r0, [r2, #16]
        0xD0, 0x01, 0xE2, 0xE1, // 0x10038: ldrd r0, [r2, #16]!
        0xF0, 0x01, 0xE2, 0xE1, // 0x1003C: strd r0, [r2, #16]!
        0xD0, 0x01, 0xC2, 0xE0, // 0x10040: ldrd r0, [r2], #16
        0xF0, 0x01, 0xC2, 0xE0, // 0x10044: strd r0, [r2], #16
        0xD3, 0x00, 0x82, 0xE1, // 0x10048: ldrd r0, [r2, r3]
        0xF3, 0x00, 0x82, 0xE1, // 0x1004C: strd r0, [r2, r3]
        0xD3, 0x00, 0xA2, 0xE1, // 0x10050: ldrd r0, [r2, r3]!
        0xF3, 0x00, 0xA2, 0xE1, // 0x10054: strd r0, [r2, r3]!
        0xD3, 0x00, 0x82, 0xE0, // 0x10058: ldrd r0, [r2], r3
        0xF3, 0x00, 0x82, 0xE0, // 0x1005C: strd r0, [r2], r3
        0x1E, 0xFF, 0x2F, 0xE1  // bx lr - satisfy code/data inference.
    };
    GTIRB Gtirb = buildGtirb(gtirb::ISA::ARM, Bytes);

    auto Souffle = runSouffle(Gtirb);
    if(!Souffle)
        FAIL();

    souffle::SouffleProgram *Prog = Souffle->get();

    unsigned int Count = 0;
    for(auto &output : *Prog->getRelation("arch.memory_access"))
    {
        MemoryAccess Result;

        // Load relation
        output >> Result.Type >> Result.Addr >> Result.SrcOp >> Result.DstOp >> Result.DirectReg
            >> Result.BaseReg >> Result.IndexReg >> Result.Mult >> Result.Offset;

        SCOPED_TRACE(Result);

        // Verify - is it expected?
        auto It = ExpectedMemoryAccesses.find(Result);
        EXPECT_FALSE(It == ExpectedMemoryAccesses.end());
        Count++;
    };

    EXPECT_EQ(Count, ExpectedMemoryAccesses.size());
}
