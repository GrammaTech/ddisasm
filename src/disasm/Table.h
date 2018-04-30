#pragma once

#include <map>
#include <string>
#include <cstdint>
#include <vector>

///
/// \class Table
///
class Table
{
public:
	///
	/// No default constructor.  
	/// Require a number of columns for the table.
	///
	Table() = delete;

	///
	/// \param 	x	The number of columns (including the key) in the table.
	///
	Table(size_t x);

	///
	/// Read an entire file into the table.
	///
	bool parseFile(const std::string& x);

	///
	/// Parse a line of text into the table.
	///
	/// It must contain the proper number of columns or an exception will be thrown.
	///
	bool parseLine(const std::string& x);

	///
	///
	///
	bool empty() const;

	///
	///
	///
	size_t size() const;

	///
	/// Add a single row of data to the table.
	///
	void push_back(std::vector<std::string> x);

	std::vector<std::vector<std::string>>::iterator begin();
	std::vector<std::vector<std::string>>::const_iterator begin() const;

	std::vector<std::vector<std::string>>::iterator end();
	std::vector<std::vector<std::string>>::const_iterator end() const;

	///
	/// Get a specific table row based on the key.  
	/// Returns an empty vector if the key is not found.
	///
	/// \param 	key	The key to find the row at.
	///
	std::vector<std::string> getRow(const std::string& key) const;

	/// 
	/// Check that the first element in each row is unique.
	///
	bool checkKeys() const;

private:
	// Storage for the table's data.
	std::vector<std::vector<std::string>> table;

	// Used for parsing CSV data.
	size_t columns{0};
};
