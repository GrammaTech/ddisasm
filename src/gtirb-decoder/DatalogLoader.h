//===- DatalogLoader.cpp ----------------------------------------*- C++ -*-===//
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
#ifndef SRC_DATALOG_DECODER_H_
#define SRC_DATALOG_DECODER_H_

#include <optional>
#include <vector>

#include <gtirb/gtirb.hpp>

class DataDecoder
{
public:
    DataDecoder() = default;
    ~DataDecoder() = default;

    template <class T>
    struct Data
    {
        gtirb::Addr Addr;
        T Item;
    };

    virtual void load(const gtirb::ByteInterval& I);

private:
    std::vector<Data<uint8_t>> Bytes;
    std::vector<Data<gtirb::Addr>> Addresses;
};

class InstructionDecoder
{
public:
    InstructionDecoder() = default;
    ~InstructionDecoder() = default;

    struct Instruction
    {
        uint64_t Address;
        long Size;
        std::string Prefix;
        std::string Name;
        std::vector<uint64_t> OpCodes;
        uint8_t ImmediateOffset;
        uint8_t DisplacementOffset;
    };

    virtual void load(const gtirb::ByteInterval& I);

protected:
    virtual std::optional<Instruction> decode(const uint8_t* bytes, uint64_t size);

private:
    std::vector<Instruction> Instructions;
    std::vector<gtirb::Addr> InvalidInstructions;
};

class SectionDecoder
{
public:
    SectionDecoder() = default;
    ~SectionDecoder() = default;

    SectionDecoder(InstructionDecoder& C, DataDecoder& D) : Code{C}, Data{D} {};

    virtual void load(const gtirb::Section& S);

private:
    DataDecoder Data;
    InstructionDecoder Code;
};

class DatalogLoader
{
public:
    DatalogLoader(const std::string& N) : Name{N} {};
    DatalogLoader(const std::string& N, SectionDecoder L) : Name{N}, Sections{L} {};
    ~DatalogLoader() = default;

    virtual void load(const gtirb::Context& C, const gtirb::Module& M);
    // std::shared_ptr<souffle::SouffleProgram> load(gtirb::Context& C, gtirb::Module& M);

private:
    std::string Name;
    SectionDecoder Sections;
};

#endif /* SRC_DATALOG_DECODER_H_ */
