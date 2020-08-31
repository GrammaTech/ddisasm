//===- DataLoader.h ---------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_CORE_DATALOADER_H_
#define SRC_GTIRB_DECODER_CORE_DATALOADER_H_

#include <vector>

#include <gtirb/gtirb.hpp>

#include "../DatalogProgram.h"
#include "../Relations.h"

// Load data sections.
class DataLoader
{
public:
    template <typename T>
    using Data = relations::Data<T>;

    enum class Pointer
    {
        DWORD = 4,
        QWORD = 8
    };

    explicit DataLoader(Pointer N) : PointerSize{N} {};
    virtual ~DataLoader(){};

    virtual void operator()(const gtirb::Module& Module, DatalogProgram& Program);

protected:
    virtual void load(const gtirb::Module& Module);
    virtual void load(const gtirb::ByteInterval& Bytes);

    // Test that a value N is a possible address.
    virtual bool address(gtirb::Addr N)
    {
        return ((N >= Min) && (N <= Max));
    };

    Pointer PointerSize;
    gtirb::Addr Min, Max;
    std::vector<Data<uint8_t>> Bytes;
    std::vector<Data<gtirb::Addr>> Addresses;
};

#endif // SRC_GTIRB_DECODER_CORE_DATALOADER_H_
