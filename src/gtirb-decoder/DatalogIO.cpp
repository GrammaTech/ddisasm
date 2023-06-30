//===- DatalogIO.h -----------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020-2023 GrammaTech, Inc.
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
#include "DatalogIO.h"

#include <souffle/RamTypes.h>

#include <fstream>
#include <list>
#include <map>

#if defined(DDISASM_SOUFFLE_PROFILING)
#include <souffle/profile/ProfileEvent.h>

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;
#endif

/**
Create a record from a string and return the record ID.
*/
souffle::RamDomain DatalogIO::insertRecord(souffle::SouffleProgram &Program,
                                           const std::string &RecordText)
{
    if(RecordText[0] != '[' || RecordText[RecordText.size() - 1] != ']')
    {
        throw std::invalid_argument("Could not parse record");
    }

    souffle::RecordTable &RecordTable = Program.getRecordTable();
    souffle::SymbolTable &SymbolTable = Program.getSymbolTable();

    // Create string without the enclosing record brackets
    std::string RemainingFieldText = RecordText.substr(1, RecordText.size() - 2);

    // There is currently no way to query souffle for the structure of the
    // record type.
    // Parsing would also be easier and more accurate if we knew the expected
    // types. This code could be wrong, for example, if a string entry is a
    // valid integer or record.
    std::vector<souffle::RamDomain> RecordData;
    std::string InferredRecordType;
    std::string Field;
    bool End = false;
    while(!End)
    {
        size_t Pos = RemainingFieldText.find(", ");
        if(Pos == std::string::npos)
        {
            Pos = RemainingFieldText.size();
            End = true;
        }
        Field = RemainingFieldText.substr(0, Pos);

        if(!End)
        {
            RemainingFieldText = RemainingFieldText.substr(Pos + 2);
        }

        enum ParseMode
        {
            PARSE_UNSIGNED,
            PARSE_SIGNED,
            PARSE_FLOAT,
            PARSE_RECORD,
            PARSE_STRING,
            PARSE_END /* Keep at end */
        };

        // We don't know what the form of the record type is. Just try parsing
        // until something works...
        for(unsigned int ParseAttempt = PARSE_UNSIGNED; ParseAttempt < PARSE_END; ParseAttempt++)
        {
            std::string InferredFieldType = "";
            try
            {
                switch(ParseAttempt)
                {
                    case PARSE_UNSIGNED:
                    {
                        // Unsigned int
                        uint64_t Number = std::stoull(Field, 0, 0);
                        RecordData.push_back(souffle::ramBitCast(Number));
                        InferredFieldType = "u";
                        break;
                    }
                    case PARSE_SIGNED:
                    {
                        // Signed int
                        int64_t Number = std::stoll(Field, 0, 0);
                        RecordData.push_back(souffle::ramBitCast(Number));
                        InferredFieldType = "i";
                        break;
                    }
                    case PARSE_FLOAT:
                    {
                        // Float
                        RecordData.push_back(souffle::ramBitCast(std::stod(Field)));
                        InferredFieldType = "f";
                        break;
                    }
                    case PARSE_RECORD:
                    {
                        // Record
                        RecordData.push_back(insertRecord(Program, Field));
                        InferredFieldType = "r";
                        break;
                    }
                    case PARSE_STRING:
                        // Nothing else worked - insert it as a string.
                        RecordData.push_back(SymbolTable.encode(Field));
                        InferredFieldType = "s";
                        break;
                }
            }
            catch(std::invalid_argument e)
            {
                // Didn't parse correctly - try parsing as a different type.
                continue;
            }

            // Parsing succeeded.
            break;
        }
    }

    return RecordTable.pack(RecordData.data(), RecordData.size());
}

bool DatalogIO::insertTuple(const std::string &TupleText, souffle::SouffleProgram &Program,
                            souffle::Relation *Relation)
{
    std::stringstream Ss(TupleText);

    souffle::tuple T(Relation);
    std::string Field;
    size_t Arity = Relation->getArity();
    for(size_t I = 0; I < Arity; I++)
    {
        if(Arity == 1)
        {
            std::getline(Ss, Field, '\n');
        }
        else if(!std::getline(Ss, Field, '\t'))
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
                case 'r':
                    T << insertRecord(Program, Field);
                    break;
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

    if(!Ss.eof() && std::getline(Ss, Field, '\t'))
    {
        std::cerr << "CSV file has more fields than expected, field '" << Field << "' is ignored"
                  << std::endl;
    }
    Relation->insert(T);
    return true;
}

void DatalogIO::serializeAttribute(std::ostream &Stream, souffle::SouffleProgram &Program,
                                   const std::string &AttrType, souffle::RamDomain Data)
{
    souffle::SymbolTable &SymbolTable = Program.getSymbolTable();
    switch(AttrType[0])
    {
        case 's':
            Stream << SymbolTable.unsafeDecode(Data);
            break;
        case 'u':
            if(AttrType == "u:address")
            {
                Stream << std::hex << souffle::ramBitCast<souffle::RamUnsigned>(Data) << std::dec;
            }
            else
            {
                Stream << souffle::ramBitCast<souffle::RamUnsigned>(Data);
            }
            break;
        case 'f':
            Stream << souffle::ramBitCast<souffle::RamFloat>(Data);
            break;
        case 'i':
            Stream << souffle::ramBitCast<souffle::RamSigned>(Data);
            break;
        case 'r':
            serializeRecord(Stream, Program, AttrType, Data);
            break;
        default:
            throw std::logic_error("Serialization for datalog type " + AttrType + " not defined");
    }
}

void DatalogIO::serializeRecord(std::ostream &Stream, souffle::SouffleProgram &Program,
                                const std::string &AttrType, souffle::RamDomain RecordId)
{
    // There is no way to look up record type information from the Datalog. We
    // have to keep a map of definitions here.
    static const std::map<std::string, std::list<std::string>> RecordTypeMap = {
        {"r:stack_var", {"s:register", "i:number"}},
    };

    auto It = RecordTypeMap.find(AttrType);
    if(It == RecordTypeMap.end())
    {
        throw std::logic_error("Serialization for datalog record type " + AttrType
                               + " not defined");
    }

    const souffle::RamDomain *Record = Program.getRecordTable().unpack(RecordId, It->second.size());

    Stream << "[";
    unsigned int I = 0;
    for(const std::string &RecordAttr : It->second)
    {
        if(I > 0)
        {
            Stream << ", ";
        }
        serializeAttribute(Stream, Program, RecordAttr, Record[I]);
        I++;
    }
    Stream << "]";
}

void DatalogIO::serializeType(std::ostream &Stream, souffle::Relation *Relation)
{
    // Construct type signature string.
    Stream << Relation->getAttrName(0) << ":" << Relation->getAttrType(0);
    for(size_t I = 1; I < Relation->getArity(); I++)
    {
        Stream << "," << Relation->getAttrName(I) << ":" << Relation->getAttrType(I);
    }
}

void DatalogIO::writeRelation(std::ostream &Stream, souffle::SouffleProgram &Program,
                              const souffle::Relation *Relation)
{
    Stream << std::showbase;

    for(souffle::tuple Tuple : *Relation)
    {
        for(size_t I = 0; I < Tuple.size(); I++)
        {
            if(I > 0)
            {
                Stream << "\t";
            }
            serializeAttribute(Stream, Program, Relation->getAttrType(I), Tuple[I]);
        }
        Stream << "\n";
    }
}

void DatalogIO::writeRelations(const std::string &Directory, const std::string &FileExtension,
                               souffle::SouffleProgram &Program,
                               const std::vector<souffle::Relation *> &Relations)
{
    std::ios_base::openmode FileMask = std::ios::out;
    for(souffle::Relation *Relation : Relations)
    {
        std::ofstream File(Directory + Relation->getName() + FileExtension, FileMask);
        writeRelation(File, Program, Relation);
        File.close();
    }
}

void DatalogIO::writeFacts(const std::string &Directory, souffle::SouffleProgram &Program)
{
    writeRelations(Directory, ".facts", Program, Program.getInputRelations());
}

void DatalogIO::writeRelations(const std::string &Directory, souffle::SouffleProgram &Program)
{
    std::string FileExtension = ".csv";
    writeRelations(Directory, FileExtension, Program, Program.getInternalRelations());
    writeRelations(Directory, FileExtension, Program, Program.getOutputRelations());
}

void DatalogIO::readRelations(souffle::SouffleProgram &Program, const std::string &Directory)
{
    // Load output relations into synthesized SouffleProgram.
    for(souffle::Relation *Relation : Program.getOutputRelations())
    {
        const std::string Path = Directory + "/" + Relation->getName() + ".csv";
        std::ifstream CSV(Path);
        if(!CSV)
        {
            std::cerr << "Error: missing output relation `" << Path << "'\n";
            continue;
        }
        std::string Line;
        while(std::getline(CSV, Line))
        {
            DatalogIO::insertTuple(Line, Program, Relation);
        }
    }
}

void DatalogIO::setProfilePath(const std::string &ProfilePath)
{
#if defined(DDISASM_SOUFFLE_PROFILING)
    souffle::ProfileEventSingleton::instance().setOutputFile(ProfilePath);
#endif
}

std::string DatalogIO::clearProfileDB()
{
#if defined(DDISASM_SOUFFLE_PROFILING)
    souffle::ProfileEventSingleton::instance().stopTimer();
    souffle::ProfileEventSingleton::instance().dump();

    // Clearing the profile path ensures the ProfileEventSingleton
    // destructor does not dump again.
    souffle::ProfileEventSingleton::instance().setOutputFile("");

    // Clear the profile database by loading an empty json file
    // (this is the only way to clear it that Souffle currently exposes)
    fs::path DbFilePath = fs::unique_path();

    std::ofstream DbFile(DbFilePath.string(), std::ios::out);
    if(!DbFile.is_open())
    {
        return "Failed to clear profile data: could not open " + DbFilePath.string();
    }
    DbFile << "{}\n";
    DbFile.close();

    souffle::ProfileEventSingleton::instance().setDBFromFile(DbFilePath.string());
    fs::remove(DbFilePath);
#endif
    return "";
}
