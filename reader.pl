:-module(reader,[read_binary/1]).

:-use_module(library(lambda)).
:-use_module(library(clpfd)).

analysis_file('souffle_main.pl').

read_binary([File|Args]):-
	(member(skip_extract,Args)->
		true
	;
		atom_concat('./elf_extract.sh ',File,Cmd),
		
		shell(Cmd)
	),
	
	read_sections(File,Sections),
	maplist(extract_section(File),Sections),
	maplist(decode_section(File),Sections,Decoded_sections),!,
	read_symbols(File,Symbols),
	collect_datalog_program([decoded_section(Symbols)|Decoded_sections],Dl_program-Rules),
	analysis_file(Analysis_file),
	read_analysis(Analysis_file,Rules-[]),

	atom_concat(File,'.dl',File3),
	save_db(single_souffle,File3,Dl_program),
	trace,
	atom_concat(File,'.bdd',File4),
	save_db(bddbddb,File4,Dl_program).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% predicates for reading elf information
read_symbols(File,Symbols_final):-
	atom_concat(File,'.symbols',File2),
	read_terms_from_filename(File2,Symbols-[]),
	maplist(\Symbol^Symbol2^(
		Symbol=symbol(Address,N,Type,Scope,Name),
		hex_to_dec(Address,Address_dec),
		atom_string(Name,NameStr),
		Symbol2=symbol(Address_dec,N,Type,Scope,NameStr)
			), Symbols, Symbols_dec),
	exclude(symbol_has_no_name,Symbols_dec,Symbols_final).
	
symbol_has_no_name(symbol(_,_,_,_,"")).

	
read_sections(File,Interesting_sections):-
	atom_concat(File,'.sections',File2),
	read_terms_from_filename(File2,Sections-[]),
	%transform the numbers to decimal
	maplist(\Section^Section2^(
		Section=section(Name,Type,Address),
		hex_to_dec(Address,Address_dec),
		Section2=section(Name,Type,Address_dec)
			), Sections, Sections_dec),
	include(section_of_interest,Sections_dec,Interesting_sections).

extract_section(File,section(Name,_Type,Address)):-
	%objcopy -O binary --only-section=.text $1 $1.text
	atomic_list_concat(['objcopy -O binary --only-section=',Name,' ',File,' ',File,Name],Cmd),
	shell(Cmd),
	%./x64show  -f=$1.text -address=0x$offset_text -omit-prefix > $1.dec
	atomic_list_concat(['./x64show  -f=',File,Name,' -address=',Address,' -omit-prefix > ',File,Name,'.dec'],Cmd2),
	shell(Cmd2).

decode_section(File,section(Name,_,_Address),decoded_section(Decoded_terms)):-
	atomic_list_concat([File,Name,'.dec'],SectionFile),
	read_terms_from_filename(SectionFile,Terms-[]),
	maplist(decode,Terms,Decoded_terms).

%for now we only get the .text section
section_of_interest(section('.text',_Type,_Address)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% decodification of instructions into a uniform format

decode(threeop32_32_32(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,[Op1,Op2,Op3])):-!.
decode(threeop64_64_32(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,[Op1,Op2,Op3])):-!.

decode(twoop128(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(twoop32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop64(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(oneop32(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])):-!.
decode(oneop64(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])):-!.
decode(oneop8(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])):-!.

decode(twoop128_64(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop128_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(twoop64_128(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop64_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop64_16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop64_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.


decode(twoop32_16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop32_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(twoop16_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(zeroop(EA,Size,_,OpCode),instruction(EA,Size,OpCode,[])):-!.
decode(ret(EA,Size,_,_),instruction(EA,Size,ret,[])):-!.

decode(oneopfloat(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])).

decode(lea64(EA,Size,_,Op1,Op2),instruction(EA,Size,lea,[Op1,Op2])):-!.
decode(lea32(EA,Size,_,Op1,Op2),instruction(EA,Size,lea,[Op1,Op2])):-!.

decode(Other,none):-format('Unrecognized instruction ~p~n',[Other]),fail.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% collect facts from the instruction list

collect_datalog_program(Decoded_sections,Dl_program-Dl_tail2):-
	Dl_program=[
		 	   type(symbol,name,4195505),
		 	   type(number,number,4195505),
		   decl('Symbols',symbol(n:name,m:number),[input]),
		   decl('Target',target(n:number,m:number),[input]),
		   decl('Jumps',jump(n:number,m:number),[input]),
		   decl('Calls',call(n:number,m:number),[input]),
		   decl('Valids',valid(n:number),[input]),
		   decl('Returns',return(n:number),[input])|Facts],
	collect_all_facts(Decoded_sections,Facts-Dl_tail2).
	
collect_all_facts([],Dl_tail-Dl_tail).
			
		
collect_all_facts([Decoded_section|More_terms],Dl_program-Dl_tail2):-
	collect_facts(Decoded_section,Dl_program-Dl_tail),
	collect_all_facts(More_terms,Dl_tail-Dl_tail2).
		
collect_facts(decoded_section(Instructions),Facts-Tail):-
	convlist(collect_symbols,Instructions,Symbols),
	convlist(collect_target,Instructions,Targets),
	convlist(collect_jump,Instructions,Jumps),
	convlist(collect_call,Instructions,Calls),
	convlist(collect_valid,Instructions,Valids),
	convlist(collect_return,Instructions,Returns),
	Facts=[

		   fact_list(Symbols),
		 
		   fact_list(Targets),
		   
		   fact_list(Jumps),
		   
		   fact_list(Calls),
		   
		   fact_list(Valids),
		   
		   fact_list(Returns)|
		   Tail].

:-dynamic collect_symbols/2.
%collect_symbols(symbol(EA,_,_,_,Name),symbol(Name,EA)).

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
	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%	
% Save the facts and the rules in different formats
	
save_db(single_souffle,File,Terms):-
	open(File,write,S),
	maplist(write_simple_rel(souffle,S),Terms),
	close(S).

save_db(bddbddb,File,Terms):-
	open(File,write,S),
	maplist(write_simple_rel(bddbddb,S),Terms),
	close(S).	
	
	
%print souffle format	
write_simple_rel(souffle,S,type(symbol,Name,_)):-
	format(S,'.symbol_type ~p~n',[Name]).	
write_simple_rel(souffle,_,type(number,_,_)).
	
write_simple_rel(souffle,S,decl(Name,Type,Options)):-
	format(S,'//~n// ~p~n//~n',[Name]),
	format(S,'.decl ~p~n',[Type]),
	functor(Type,Id,_),
	(member(output(stdout),Options)->
		format(S,'.output  ~p(IO=stdout)~n',[Id])
		;
		true
	).
	
%write_simple_rel(souffle,S,output(Name,file(FileName))):-
%	format(S,'.output  ~p(filename="~p")~n',[Name,FileName]).
			

	
write_simple_rel(souffle,S,fact_list(List)):-
	maplist(\Term^write_term(S,Term,[fullstop(true),nl(true),quoted(true)]),List),
	format(S,'~n',[]).

write_simple_rel(souffle,S,rule(Clause,Vars)):-	
	maplist(unify,Vars),
	adapt_negations(Clause,Clause2),
	write_term(S,Clause2,[fullstop(true),nl(true)]).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%	
% print ddbdbbd format	
	

write_simple_rel(bddbddb,S,type(_,Name,Max)):-
	format(S,'~p ~p~n',[Name,Max]).	
		
write_simple_rel(bddbddb,S,decl(Name,Type,Options)):-
	format(S,'#~n### ~p~n#~n',[Name]),
	(member(output(stdout),Options)->
		format(S,'~p output~n',[Type])
		;
		(member(input,Options)->
			format(S,'~p input~n',[Type])
		;
			format(S,'~p~n',[Type])
		)
	).


write_simple_rel(bddbddb,S,fact_list(List)):-
	maplist(\Term^write_term(S,Term,[fullstop(true),nl(true),quoted(true)]),List),
	format(S,'~n',[]).

write_simple_rel(bddbddb,S,rule(Clause,Vars)):-	
	maplist(unify,Vars),
	adapt_negations(Clause,Clause2),
	(Clause2=..[Op,Head,Body]->
		format(S,'~p ~p ~p.~n',[Head,Op,Body])
		;
		write_term(S,Clause2,[fullstop(true),nl(true)])
	).

	
	

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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% basic read and writing


read_analysis(File,RulesTail):-
	open(File,read,S),
	read_analysis_1(S,RulesTail),
	close(S).

read_analysis_1(S,Terms-Tail) :-
	read_term(S,Term,[variable_names(Vars)]),
	( 
	  Term == end_of_file -> 
	    Terms = Tail
	;
	    (Vars\=[]->
	      Terms = [rule(Term,Vars)|Terms_aux]
	      ;
	      Terms = [Term|Terms_aux]
	    ),
	    read_analysis_1(S,Terms_aux-Tail)
	).
	
read_terms_from_filename(FileName,Terms):-
	open(FileName,read,S),
	read_terms_from_file(S,Terms),
	close(S).
	
read_terms_from_file(S,Terms-Tail) :-
	read_line_to_string(S,String),
	string_lower(String,Str_lower),
	remove_paren(Str_lower,Str_clean),
	term_string(Term,Str_clean),
	( 
	  Term == end_of_file -> 
	    Terms = Tail
	;
	    Terms = [Term|Terms_aux],
	    read_terms_from_file(S,Terms_aux-Tail)
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
	
%save_terms(File,Terms):-
%	open(File,write,S),
%	maplist(\Term^write_term(S,Term,[fullstop(true),nl(true)]),Terms),
%	close(S).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% auxiliary predicates
hex_to_dec(Hex,Dec):-
	hex_bytes(Hex,Bytes),
	byte_list_to_num(Bytes,0,Dec).

byte_list_to_num([],Accum,Accum).
byte_list_to_num([Byte|Bytes],Accum,Dec):-
	Accum2 is Byte+256*Accum,
	byte_list_to_num(Bytes,Accum2,Dec).

