//===- CompositeLoader.cpp ----------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_COMPOSITELOADER_H_
#define SRC_GTIRB_DECODER_COMPOSITELOADER_H_

#include <gtirb/gtirb.hpp>
#include <optional>
#include <string>
#include <vector>

#include "DatalogProgram.h"
#include "Relations.h"

class CompositeLoader
{
public:
    explicit CompositeLoader(const std::string& N) : Name{N}, Loaders{} {};
    ~CompositeLoader() = default;

    // Common type definition for functions/functors that populate datalog relations.
    using Loader = std::function<void(const gtirb::Module&, DatalogProgram&)>;

    // Add function to this composite loader.
    void add(Loader Fn)
    {
        Loaders.push_back(Fn);
    }

    // Add function object to this composite loader.
    template <typename T, typename... Args>
    void add(Args&&... A)
    {
        Loaders.push_back(T{std::forward<Args>(A)...});
    }

    // Build a DatalogProgram (i.e. SouffleProgram).
    std::optional<DatalogProgram> load(const gtirb::Module& Module)
    {
        if(auto SouffleProgram =
               std::shared_ptr<souffle::SouffleProgram>(souffle::ProgramFactory::newInstance(Name)))
        {
            DatalogProgram Program{SouffleProgram};
            return operator()(Module, Program);
        }
        return std::nullopt;
    }

    // Implement loader interface for composition of CompositeLoaders.
    std::optional<DatalogProgram> operator()(const gtirb::Module& Module, DatalogProgram& Program)
    {
        for(auto& Loader : Loaders)
        {
            Loader(Module, Program);
        }
        return Program;
    }

private:
    std::string Name;
    std::vector<Loader> Loaders;
};

#endif // SRC_GTIRB_DECODER_COMPOSITELOADER_H_
