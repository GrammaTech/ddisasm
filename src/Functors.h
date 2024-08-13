//===- Functors.h -----------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2022 GrammaTech, Inc.
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
#ifndef SRC_FUNCTORS_H_
#define SRC_FUNCTORS_H_
#include <gtirb/gtirb.hpp>

#include "souffle/SouffleInterface.h"

#ifndef __has_declspec_attribute
#define __has_declspec_attribute(x) 0
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#if defined(_MSC_VER) || __has_declspec_attribute(dllexport)
#define EXPORT _declspec(dllexport)
#elif defined(__GNUC__) || __has_attribute(visibility)
#define EXPORT __attribute__((visibility("default")))
#else
#define EXPORT
#endif

// C interface is used for accessing the functors from datalog
extern "C"
{
    EXPORT uint64_t functor_data_valid(uint64_t EA, size_t Size);

    EXPORT uint64_t functor_data_unsigned(uint64_t EA, size_t Size);
    EXPORT uint64_t functor_data_u8(uint64_t EA);
    EXPORT uint64_t functor_data_u16(uint64_t EA);
    EXPORT uint64_t functor_data_u32(uint64_t EA);
    EXPORT uint64_t functor_data_u64(uint64_t EA);

    EXPORT int64_t functor_data_signed(uint64_t EA, size_t Size);
    EXPORT int64_t functor_data_s8(uint64_t EA);
    EXPORT int64_t functor_data_s16(uint64_t EA);
    EXPORT int64_t functor_data_s32(uint64_t EA);
    EXPORT int64_t functor_data_s64(uint64_t EA);

    EXPORT uint64_t functor_aligned(uint64_t EA, size_t Size);

    EXPORT uint64_t functor_choose_max(int64_t Val1, int64_t Val2, uint64_t Id1, uint64_t Id2);

    EXPORT int64_t functor_thumb32_branch_offset(uint32_t Instruction);

    /**
    Format an unsigned integer as a string in its hex representation
    */
    EXPORT souffle::RamDomain to_string_hex(souffle::SymbolTable* symbolTable,
                                            souffle::RecordTable* recordTable,
                                            souffle::RamDomain Value);
}

class FunctorContextManager
{
public:
    FunctorContextManager()
#ifdef __EMBEDDED_SOUFFLE__
    {
    }
#else
    {
        // Load GTIRB from the debug directory when the Context is initialized
        // if running in the interpreter.
        loadGtirb();
    }
#endif /* __EMBEDDED_SOUFFLE__ */

    const gtirb::ByteInterval* getByteInterval(uint64_t EA, size_t Size);
    void readData(uint64_t EA, uint8_t* Buffer, size_t Count);
    void useModule(const gtirb::Module* M);
    bool IsBigEndian = false;

private:
    const gtirb::Module* Module = nullptr;

#ifndef __EMBEDDED_SOUFFLE__
    void loadGtirb(void);
    std::unique_ptr<gtirb::Context> GtirbContext;
#endif
};

extern FunctorContextManager FunctorContext;

#endif // SRC_FUNCTORS_H_
