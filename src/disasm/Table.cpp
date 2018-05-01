#include "Table.h"
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <cassert>
#include <fstream>
#include <iostream>

Table::Table(size_t x) : columns{x}
{
    assert(this->columns > 0);
}

bool Table::parseFile(const std::string& path)
{
    std::ifstream ifs(path.c_str());

    if(ifs.is_open() == true)
    {
        std::string line;
        auto parseSuccess = true;

        while(parseSuccess == true && std::getline(ifs, line))
        {
            parseSuccess = this->parseLine(line);
        }

        return parseSuccess;
    }

    std::cerr << "[FAILURE] Failed to open file: \"" << path << "\"." << std::endl;
    return false;
}

bool Table::parseLine(const std::string& x)
{
    std::vector<std::string> row;
    boost::split(row, x, boost::is_any_of(",\t"));

    if(row.size() == this->columns)
    {
        this->push_back(std::move(row));
        return true;
    }

    std::cerr << "[FAILURE] Could not parse output line: \"" << x << "\".  Read " << row.size()
              << " columns, expected " << this->columns << "." << std::endl;
    return false;
}

bool Table::empty() const
{
    return this->table.empty();
}

size_t Table::size() const
{
    return this->table.size();
}

void Table::push_back(std::vector<std::string> x)
{
    this->table.push_back(std::move(x));
}

std::vector<std::vector<std::string>>::iterator Table::begin()
{
    return std::begin(this->table);
}

std::vector<std::vector<std::string>>::const_iterator Table::begin() const
{
    return std::begin(this->table);
}

std::vector<std::vector<std::string>>::iterator Table::end()
{
    return std::end(this->table);
}

std::vector<std::vector<std::string>>::const_iterator Table::end() const
{
    return std::end(this->table);
}

std::vector<std::string> Table::getRow(const std::string& key) const
{
    auto found = std::find_if(std::begin(this->table), std::end(this->table), [&key](auto element) {
        return (element.empty() == false) && (element[0] == key);
    });

    if(found != std::end(this->table))
    {
        return *found;
    }

    return std::vector<std::string>{};
}

bool Table::checkKeys() const
{
    std::map<std::string, size_t> hash;

    for(auto& i : this->table)
    {
        hash[i[0]]++;

        if(hash[i[0]] > 1)
        {
            // Duplicate found.
            return false;
        }
    }

    // No duplicates found.
    return true;
}
