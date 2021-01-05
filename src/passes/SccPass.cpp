//===- SccPass.cpp ----------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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
#include "SccPass.h"

#include <boost/config.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/strong_components.hpp>

#include "../AuxDataSchema.h"

class KeepIntraProcedural
{
public:
    template <typename Edge>
    bool operator()(const Edge& E) const
    {
        const gtirb::EdgeLabel& L = *static_cast<const gtirb::EdgeLabel*>(E.get_property());
        if(L)
        {
            gtirb::EdgeType Type = std::get<gtirb::EdgeType>(*L);
            return Type == gtirb::EdgeType::Branch || Type == gtirb::EdgeType::Fallthrough;
        }
        return false;
    }
};

void computeSCCs(gtirb::Module& module)
{
    SccMap Sccs;
    auto& Cfg = module.getIR()->getCFG();
    KeepIntraProcedural Filter;
    boost::filtered_graph<gtirb::CFG, KeepIntraProcedural> CfgFiltered(Cfg, Filter);

    typedef std::map<gtirb::CFG::vertex_descriptor, size_t> PropertyMap;

    // Property map to store SCCs
    PropertyMap SccComponents;
    boost::associative_property_map<PropertyMap> SccComponentsMap(SccComponents);

    // Create property map with indexes.
    // This is needed because we use lists for storing vertices.
    PropertyMap Index;
    boost::associative_property_map<PropertyMap> IndexMap(Index);
    size_t I = 0;
    for(auto Vertex : boost::make_iterator_range(boost::vertices(Cfg)))
    {
        boost::put(IndexMap, Vertex, I++);
    }

    // Compute the Sccs
    strong_components(CfgFiltered, SccComponentsMap, vertex_index_map(IndexMap));

    // Store them in AuxData
    for(auto Vertex : boost::make_iterator_range(vertices(Cfg)))
    {
        gtirb::Node* N = Cfg[Vertex];
        Sccs[N->getUUID()] = SccComponents[Vertex];
    }
    module.addAuxData<gtirb::schema::Sccs>(std::move(Sccs));
}
