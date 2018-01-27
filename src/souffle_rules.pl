.symbol_type name

.number_type address

// 'Symbols'
.decl symbol(ea:address,n:number,type:symbol,scope:symbol,name:symbol)
#include "symbol.facts"



.decl possible_target(ea:address)
#include "possible_target.facts"

// 'Next'
.decl next(n:address,m:address)
#include "next.facts"
// 'Jumps'
.decl inconditional_jump(n:address)
#include "inconditional_jump.facts"

.decl direct_jump(n:address,m:address)
#include "direct_jump.facts"
// 'Calls'
.decl direct_call(n:address,m:address)
#include "direct_call.facts"

// 'Invalid adresses'
.decl invalid(n:address)
// 'Valid'
#include "invalid.facts"

// 'Returns'
.decl return(n:address)
#include "return.facts"

.decl instruction_text(n:address,name:symbol)
#include "instruction_text.facts"



.decl function_symbol(ea:address,name:symbol)
.output function_symbol(IO=stdout)

function_symbol(EA,Name):-
	symbol(EA,_,"func",_,Name).

possible_target(EA):-
	function_symbol(EA,_).
	
	
.decl maybe_valid(n:address)

//we can compute maybe_valid from next (hopefully reducing reading time)
maybe_valid(N):-
	next(N,_).
		
		
.decl fallthrough(o:address,d:address)

fallthrough(From,To):-
	next(From,To),
	!return(From),
	!inconditional_jump(From).
			
// I am faced with two options, cosider possible targets of things that I know are code
// or consider all possible targets of possibly not code
// If I restrict the targets I might get a circular definition (non-monotonic)
// because I am using !possible_target to compute valid4sure

// propagate from entry points
// following direct jumps and direct calls

.decl valid4sure(n:address,start:address)
//.output valid4sure(IO=stdout)

//for sure might be an overstatement
valid4sure(EA,EA):-
	possible_target(EA),
	maybe_valid(EA).

valid4sure(EA,Start):-
	valid4sure(EA2,Start),
	fallthrough(EA2,EA),
	!possible_target(EA),
	maybe_valid(EA).
	
valid4sure(EA,EA):-
	valid4sure(EA2,_),
	direct_jump(EA2,EA),
	maybe_valid(EA).
	
valid4sure(EA,EA):-
	valid4sure(EA2,_),
	direct_call(EA2,EA),
	maybe_valid(EA).	


// forbid overlaps with valid4sure instructions
// grow the initial invalid set 
// there are many ways of doing this, many possible orders

.decl overlap(ea:address,ea_origin:address)


//this is kind of ugly but for now it seems to achieve much better performance
overlap(EA2+1,EA2):-
	//this should limit the scope even more
	valid4sure(EA2,_),
	next(EA2,End),
	EA2+1 < End.
overlap(EA+1,EA2):-
	overlap(EA,EA2),
	next(EA2,End),
	EA+1 < End.
	
invalid(EA):- 
	valid4sure(Ini,_),
	overlap(EA,Ini),
	maybe_valid(EA),
	!valid4sure(EA,_).

//transitively invalid

.decl invalid_transitive(n:address)
//.output invalid_transitive(IO=stdout)

invalid_transitive(EA):-invalid(EA).
invalid_transitive(From):-
	invalid_transitive(To),
	(
		fallthrough(From,To)
	;
		direct_jump(From,To)
	;
		direct_call(From,To)
	).
	



.decl maybe_valid2(n:address)
//.output maybe_valid2(IO=stdout)

maybe_valid2(EA):-
	maybe_valid(EA),
	!invalid_transitive(EA).

.decl print(ea:address,name:symbol,parent:address)
.output print(IO=stdout)

print(EA,Name,Parent):-
	maybe_valid2(EA),
	(
		valid4sure(EA,Parent)
	;
		!valid4sure(EA,_),Parent=0
	),
	instruction_text(EA,Name).
