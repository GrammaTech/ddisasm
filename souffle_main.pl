
% input relations
%.decl entry(n:number)

%.decl target(n:number,m:number)

%.decl jumps(n:number,m:number)

%.decl call(n:number,m:number)

%.decl valid(n:number)
%.decl return(n:number)




decl('Successor',succ(n:number,m:number),[input]).

succ(From,To) :- target(From,To), \+return(From).
succ(From,To) :- call(From,To).
%succ(From,To) :- fallthroughs(From,To), calls(From,Remote), may_return(Remote).

decl('Reachable',reachable(n:number,m:number),[output(stdout)]).

%reachable(From,From) :- valid(From).
reachable(From,To) :- succ(From,To).
reachable(From,To) :- succ(From,In),reachable(In,To).


decl('Reachable from symbol',reachable_from_symbol(m:name,n:number),[output(stdout)]).


%reachable_from_symbol(Name,Reach) :- symbol(Name,EA),reachable(EA,Reach).

%decl('Symbol reachable from symbol',symbol_reachable_from_symbol(m:name,n:name),[output(stdout)]).

%symbol_reachable_from_symbol(Name,Name2) :- symbol(Name,EA),symbol(Name2,EA2),reachable(EA,EA2).

