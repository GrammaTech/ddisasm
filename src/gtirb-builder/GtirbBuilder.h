//===- GtirbBuilder.h --------------------------------------------*- C++ -*-===//
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

#ifndef GTIRB_BUILDER_H_
#define GTIRB_BUILDER_H_

#include <LIEF/LIEF.hpp>
#include <boost/filesystem.hpp>
#include <gtirb/gtirb.hpp>

#include "../AuxDataSchema.h"

namespace fs = boost::filesystem;

class GtirbBuilder
{
public:
    GtirbBuilder(std::string Path, std::shared_ptr<LIEF::Binary> Binary);

    struct GTIRB
    {
        std::unique_ptr<gtirb::Context> Context;
        gtirb::IR* IR;
    };

    static gtirb::ErrorOr<GTIRB> read(std::string Path);
    virtual gtirb::ErrorOr<GTIRB> build();

    /// \enum build_error
    /// \brief Specifies various failure modes when loading a binary.
    enum class build_error
    {
        FileNotFound = 1, ///< The file path provided does not exists.
        ParseError,       ///< The input file could not be parsed with LIEF.
        NotSupported,     ///< The input file was parsed, but is not supported.
    };

protected:
    virtual void initModule();
    virtual void buildSections() = 0;
    virtual void buildSymbols() = 0;
    virtual void addEntryBlock() = 0;
    virtual void addAuxData() = 0;

    gtirb::FileFormat format();
    gtirb::ISA isa();

    std::string Path;
    std::shared_ptr<LIEF::Binary> Binary;
    std::unique_ptr<gtirb::Context> Context;
    gtirb::IR* IR;
    gtirb::Module* Module;
};

/// \brief The error category used to represent build failures.
/// \return The build failure error category.
const std::error_category& buildErrorCategory();

/// \brief Makes an \ref std::error_code object from an \ref GtirbBuilder::build_error object.
/// \return The error code.
inline std::error_code make_error_code(GtirbBuilder::build_error E)
{
    return std::error_code(static_cast<int>(E), buildErrorCategory());
}

namespace std
{
    template <>
    struct is_error_code_enum<GtirbBuilder::build_error> : std::true_type
    {
    };
} // namespace std

#endif // GTIRB_BUILDER_H_
