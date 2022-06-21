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
#include "DatalogProgram.h"

#include <souffle/RamTypes.h>

#include <fstream>
#include <gtirb/gtirb.hpp>

#include "../AuxDataSchema.h"
#include "CompositeLoader.h"
#include "core/ModuleLoader.h"

std::map<DatalogProgram::Target, DatalogProgram::Factory> &DatalogProgram::loaders()
{
    static std::map<Target, Factory> Loaders;
    return Loaders;
}

std::optional<DatalogProgram> DatalogProgram::load(const gtirb::Module &Module)
{
    auto Target = std::make_tuple(Module.getFileFormat(), Module.getISA(), Module.getByteOrder());

    auto Factories = loaders();
    if(auto It = Factories.find(Target); It != Factories.end())
    {
        auto Loader = (It->second)();
        return Loader.load(Module);
    }
    return std::nullopt;
}

bool DatalogProgram::insertTuple(std::stringstream &TupleText, souffle::Relation *Relation)
{
    souffle::tuple T(Relation);
    for(size_t I = 0; I < Relation->getArity(); I++)
    {
        std::string Field;
        if(Relation->getArity() == 1)
        {
            Field = TupleText.str();
        }
        else if(!std::getline(TupleText, Field, '\t'))
        {
            std::cerr << "CSV file has less fields than expected" << std::endl;
            return false;
        }
        try
        {
            switch(Relation->getAttrType(I)[0])
            {
                case 's':
                {
                    T << Field;
                    break;
                }
                case 'i':
                {
                    int64_t Number = std::stoll(Field, 0, 0);
                    T << Number;
                    break;
                }
                case 'u':
                {
                    uint64_t Number = std::stoull(Field, 0, 0);
                    T << Number;
                    break;
                }
                case 'f':
                {
                    T << std::stod(Field);
                    break;
                }
                default:
                    std::cerr << "Cannot parse field type " << Relation->getAttrType(I)
                              << std::endl;
                    return false;
            }
        }
        catch(std::invalid_argument e)
        {
            std::cerr << "Failed to parse " << I + 1 << "-th field: '" << Field << "'" << std::endl;
            return false;
        }
    }
    Relation->insert(T);
    return true;
}

void DatalogProgram::readHintsFile(const std::string FileName)
{
    std::ifstream HintsFile(FileName);

    if(!HintsFile)
    {
        std::cerr << "Error: could not find hints file `" << FileName << "'\n";
        return;
    }

    std::string Line;
    int LineNumber = 0;
    while(std::getline(HintsFile, Line))
    {
        ++LineNumber;
        std::stringstream Row(Line);
        std::string RelationName;
        if(!std::getline(Row, RelationName, '\t'))
        {
            std::cerr << "Warning: ignoring hint in line " << LineNumber << ": '" << Line << "'\n";
            continue;
        }
        souffle::Relation *Relation = Program->getRelation(RelationName);
        if(!Relation)
        {
            std::cerr << "Warning: ignoring hint in line " << LineNumber << ": unknown relation "
                      << RelationName << std::endl;
            continue;
        }
        if(!insertTuple(Row, Relation))
        {
            std::cerr << "Warning: ignoring hint in line " << LineNumber << ": bad format"
                      << std::endl;
            continue;
        }
    }
}

std::vector<DatalogProgram::Target> DatalogProgram::supportedTargets()
{
    static std::vector<DatalogProgram::Target> Targets;

    for(auto Factory : DatalogProgram::loaders())
    {
        Targets.push_back(Factory.first);
    }

    return Targets;
}

void DatalogProgram::writeRelation(std::ostream &Stream, const souffle::Relation *Relation)
{
    souffle::SymbolTable &SymbolTable = Relation->getSymbolTable();
    std::vector<bool> HexFields;
    for(size_t I = 0; I < Relation->getArity(); I++)
    {
        std::string FieldType = Relation->getAttrType(I);
        HexFields.push_back(FieldType == "u:address");
    }
    Stream << std::showbase;

    for(souffle::tuple Tuple : *Relation)
    {
        for(size_t I = 0; I < Tuple.size(); I++)
        {
            if(I > 0)
            {
                Stream << "\t";
            }
            switch(Relation->getAttrType(I)[0])
            {
                case 's':
                    Stream << SymbolTable.unsafeDecode(Tuple[I]);
                    break;
                case 'u':
                    if(HexFields[I])
                    {
                        Stream << std::hex << souffle::ramBitCast<souffle::RamUnsigned>(Tuple[I])
                               << std::dec;
                    }
                    else
                    {
                        Stream << souffle::ramBitCast<souffle::RamUnsigned>(Tuple[I]);
                    }
                    break;
                case 'f':
                    Stream << souffle::ramBitCast<souffle::RamFloat>(Tuple[I]);
                    break;
                case 'i':
                    Stream << Tuple[I];
                    break;
                default:
                    throw std::logic_error("Serialization for datalog type "
                                           + std::string(Relation->getAttrType(I))
                                           + " not defined");
            }
        }
        Stream << "\n";
    }
}

void DatalogProgram::writeFacts(const std::string &Directory)
{
    std::ios_base::openmode FileMask = std::ios::out;
    for(souffle::Relation *Relation : Program->getInputRelations())
    {
        std::ofstream File(Directory + Relation->getName() + ".facts", FileMask);
        writeRelation(File, Relation);
        File.close();
    }
}

void DatalogProgram::writeRelations(const std::string &Directory)
{
    std::ios_base::openmode FileMask = std::ios::out;
    for(souffle::Relation *Relation : Program->getOutputRelations())
    {
        std::ofstream File(Directory + Relation->getName() + ".csv", FileMask);
        writeRelation(File, Relation);
        File.close();
    }
}

void DatalogProgram::writeFacts(gtirb::Module &Module)
{
    std::map<std::string, std::tuple<std::string, std::string>> Relations;

    for(souffle::Relation *Relation : Program->getInputRelations())
    {
        if(Relation->getArity() == 0)
        {
            continue;
        }

        // Construct type signature string.
        std::stringstream Type;
        Type << "<" << std::string(Relation->getAttrType(0));
        for(size_t I = 1; I < Relation->getArity(); I++)
        {
            Type << "," << Relation->getAttrType(I);
        }
        Type << ">";

        // Write CSV to buffer.
        std::stringstream Csv;
        writeRelation(Csv, Relation);

        // TODO: Compress CSV.

        Relations[Relation->getName()] = {Type.str(), Csv.str()};
    }

    Module.addAuxData<gtirb::schema::SouffleFacts>(std::move(Relations));
}

void DatalogProgram::writeRelations(gtirb::Module &Module)
{
    std::map<std::string, std::tuple<std::string, std::string>> Relations;

    for(souffle::Relation *Relation : Program->getOutputRelations())
    {
        if(Relation->getArity() == 0)
        {
            continue;
        }

        // Construct type signature string.
        std::stringstream Type;
        Type << "<" << std::string(Relation->getAttrType(0));
        for(size_t I = 1; I < Relation->getArity(); I++)
        {
            Type << "," << Relation->getAttrType(I);
        }
        Type << ">";

        // Write CSV to buffer.
        std::stringstream Csv;
        writeRelation(Csv, Relation);

        // TODO: Compress CSV.

        Relations[Relation->getName()] = {Type.str(), Csv.str()};
    }

    Module.addAuxData<gtirb::schema::SouffleOutputs>(std::move(Relations));
}
