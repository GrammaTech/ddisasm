
% input relations
%.decl entry(n:number)

%.decl target(n:number,m:number)

%.decl jumps(n:number,m:number)

%.decl call(n:number,m:number)

%.decl valid(n:number)
%.decl return(n:number)




decl('Successor',succ(n:number,m:number)).

succ(From,To) :- target(From,To), \+return(From).
succ(From,To) :- call(From,To).
%succ(From,To) :- fallthroughs(From,To), calls(From,Remote), may_return(Remote).

decl('Reachable',reachable(n:number,m:number)).
output(reachable,stdout).


reachable(From,From) :- valid(From).
reachable(From,To) :- succ(From,To).
reachable(From,To) :- succ(From,In),reachable(In,To).


decl('Reachable from entry',reachable_from_entry(n:number)).
output(reachable_from_entry,stdout).

reachable_from_entry(EA) :- entry(Entry),reachable(Entry,EA).



