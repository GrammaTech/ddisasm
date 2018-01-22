:-module(reader,[read_asm/1]).

:-use_module(library(lambda)).
:-use_module(library(clpfd)).

analysis_file('souffle_main.pl').

read_asm(File) :-
	atom(File),
	atom_concat(File,'.pl',File2),
	atom_concat(File,'.dl',File3),
	!,
	open(File,read,S),
	read_asm_from_file(S,Terms),
	close(S),
	maplist(decode,Terms,Decoded_terms),
	collect_datalog_program(Decoded_terms,Dl_program),
	%foldl(collect_facts,Decode_terms,[],Facts),
	save_terms(File2,Decoded_terms),
	save_db(single_souffle,File3,Dl_program).
	
	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% basic read and writing
read_asm_from_file(S,Terms) :-
	read_line_to_string(S,String),
	string_lower(String,Str_lower),
	remove_paren(Str_lower,Str_clean),
	term_string(Term,Str_clean),
	( 
	  Term == end_of_file -> 
	    Terms = []
	;
	    Terms = [Term|Terms_aux],
	    read_asm_from_file(S,Terms_aux)
	).

remove_paren(Str,Str_clean):-
	string_codes(Str, Codes),
	clean_codes(Codes,Codes2),
	string_codes(Str_clean,Codes2).
	
clean_codes([],[]).
clean_codes([40,41|Rest],Rest2):-!,
	clean_codes(Rest,Rest2).
clean_codes([Other|Rest],[Other|Rest2]):-	
	clean_codes(Rest,Rest2).
	
save_terms(File,Terms):-
	open(File,write,S),
	maplist(\Term^write_term(S,Term,[fullstop(true),nl(true)]),Terms),
	close(S).


decode(twoop32(EA,Size,0,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])).
decode(twoop64(EA,Size,0,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])).
decode(twoop8(EA,Size,0,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])).

decode(oneop32(EA,Size,0,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])).
decode(oneop64(EA,Size,0,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])).
decode(oneop8(EA,Size,0,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])).

decode(twoop64_32(EA,Size,0,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])).
decode(twoop64_8(EA,Size,0,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])).
decode(twoop32_8(EA,Size,0,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])).

decode(zeroop(EA,Size,0,OpCode),instruction(EA,Size,OpCode,[])).
decode(ret(EA,Size,0,0),instruction(EA,Size,ret,[])).

decode(lea64(EA,Size,0,Op1,Op2),instruction(EA,Size,lea,[Op1,Op2])).
decode(lea32(EA,Size,0,Op1,Op2),instruction(EA,Size,lea,[Op1,Op2])).

decode(entry(EA),entry(EA)).

decode(Other,none):-format('Unrecognized instruction ~p~n',[Other]),fail.

	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%	
% Save the facts and the rules in different formats
	
save_db(single_souffle,File,Terms):-
	open(File,write,S),
	maplist(write_simple_souffle_rel(S),Terms),
	close(S).
	
	
write_simple_souffle_rel(S,decl(Name,Type)):-
	format(S,'//~n// ~p~n//~n',[Name]),
	format(S,'.decl ~p~n',[Type]).

write_simple_souffle_rel(S,output(Name,stdout)):-
	format(S,'.output  ~p(IO=stdout)~n',[Name]).
write_simple_souffle_rel(S,output(Name,file(FileName))):-
	format(S,'.output  ~p(filename="~p")~n',[Name,FileName]).
			
write_simple_souffle_rel(S,output(Name,file(FileName))):-
	format(S,'.output  ~p(filename="~p")~n',[Name,FileName]).
	
write_simple_souffle_rel(S,fact_list(List)):-
	maplist(\Term^write_term(S,Term,[fullstop(true),nl(true)]),List),
	format(S,'~n',[]).
	

write_simple_souffle_rel(S,rule(Clause,Vars)):-	
	maplist(unify,Vars),
	adapt_negations(Clause,Clause2),
	write_term(S,Clause2,[fullstop(true),nl(true)]).

adapt_negations(Clause,Clause2):-
	Clause=..[':-',Head,Body],!,
	adapt_body(Body,Body2),
	Clause2=..[':-',Head,Body2].
adapt_negations(Clause,Clause).	
	
adapt_body(Single,Single2):-
	\+functor(Single,',',_),!,
	adapt_single(Single,Single2).
adapt_body((Pred,Tail),(Pred2,Tail2)):-
	adapt_single(Pred,Pred2),
	adapt_body(Tail,Tail2).

adapt_single(\+Pred,'!'(Pred)):-!.
adapt_single(Pred,Pred).
	
unify(A=A).	

	
read_asm(CRs,_Terms) :-
	throw(err(unknown_crs_format,read_crs/2,[crs=CRs])).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% collect facts from the instruction list

collect_datalog_program(Decoded_terms,Dl_program):-
	collect_facts(Decoded_terms,Dl_program-Rules),
	analysis_file(File),
	open(File,read,S),
	read_analysis(S,Rules),
	close(S).

read_analysis(S,Terms) :-
	read_term(S,Term,[variable_names(Vars)]),
	( 
	  Term == end_of_file -> 
	    Terms = []
	;
	    (Vars\=[]->
	      Terms = [rule(Term,Vars)|Terms_aux]
	      ;
	      Terms = [Term|Terms_aux]
	    ),
	    read_analysis(S,Terms_aux)
	).	
	
	
collect_facts(Instructions,Facts-Tail):-
	convlist(collect_entry,Instructions,Entries),
	convlist(collect_target,Instructions,Targets),
	convlist(collect_jump,Instructions,Jumps),
	convlist(collect_call,Instructions,Calls),
	convlist(collect_valid,Instructions,Valids),
	convlist(collect_return,Instructions,Returns),
	Facts=[decl('Entry',entry(n:number)),
		   fact_list(Entries),
		   decl('Target',target(n:number,m:number)),
		   fact_list(Targets),
		   decl('Jumps',jump(n:number,m:number)),
		   fact_list(Jumps),
		   decl('Calls',call(n:number,m:number)),
		   fact_list(Calls),
		   decl('Valids',valid(n:number)),
		   fact_list(Valids),
		   decl('Returns',return(n:number)),
		   fact_list(Returns)|
		   Tail].


collect_entry(entry(EA),entry(EA)).

collect_target(instruction(EA,Size,_OpCode,_),target(EA,EA2)):-
	EA2 #= EA+Size.
%for now we will do this later	using the other prediacates
%	OpCode\=ret,
%	OpCode\=jmp,
%	OpCode\=halt,

collect_jump(instruction(EA,_Size,Opcode,[immediate64(Dest,_,_)]),jump(EA,Dest)):-
	member(Opcode,[jmp,jnz,jz,jge,jna]).
	
collect_call(instruction(EA,_Size,call,[immediate64(Dest,_,_)]),call(EA,Dest)).

collect_valid(instruction(EA,_,_,_),valid(EA)).

collect_return(instruction(EA,_Size,ret,[]),return(EA)).
	





