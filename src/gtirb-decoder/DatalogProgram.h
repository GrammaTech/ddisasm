//===- DatalogProgram.h -----------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_DATALOGPROGRAM_H_
#define SRC_GTIRB_DECODER_DATALOGPROGRAM_H_

#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>

#include <gtirb/gtirb.hpp>
#include <map>
#include <memory>
#include <string>
#include <tuple>

class CompositeLoader;

class DatalogProgram
{
public:
    explicit DatalogProgram(std::shared_ptr<souffle::SouffleProgram> P) : Program{P} {};
    ~DatalogProgram() = default;

    static std::optional<DatalogProgram> load(const gtirb::Module& Module);

    template <typename T>
    void insert(const std::string& Name, const T& Data)
    {
        if(auto* Relation = Program->getRelation(Name))
        {
            for(const auto Element : Data)
            {
                souffle::tuple Row(Relation);
                Row << Element;
                Relation->insert(Row);
            }
        }
    }

    void writeFacts(const std::string& Directory);

    void writeRelations(const std::string& Directory)
    {
        Program->printAll(Directory);
    }

    void threads(unsigned int N)
    {
        Program->setNumThreads(N);
    }

    void run()
    {
        Program->run();
    }

    souffle::SouffleProgram* get()
    {
        return Program.get();
    }

    // Loader factory registration.
    using Target = std::tuple<gtirb::FileFormat, gtirb::ISA>;
    using Factory = std::function<CompositeLoader()>;

    static void registerLoader(Target T, Factory F)
    {
        loaders()[T] = F;
    }

private:
    static std::map<Target, Factory>& loaders();

    std::shared_ptr<souffle::SouffleProgram> Program;
};

#endif // SRC_GTIRB_DECODER_DATALOGPROGRAM_H_
