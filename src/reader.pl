:-module(reader,[read_binary/1]).

:-use_module(library(lambda)).
:-use_module(library(clpfd)).

analysis_file('souffle_main.pl').

read_binary([File|Args]):-
	format('Extracting symbols and sections from binary~n',[]),
    (member(skip_extract,Args)->
	 true
     ;
     atom_concat('./elf_extract.sh ',File,Cmd),
     
     shell(Cmd)
    ),
    format('Reading symbols~n',[]),
    read_symbols(File,Symbols),

    format('Storing symbols~n',[]),
    file_directory_name(File, Dir),
    save_db(souffle,Dir,[fact_list(symbol,Symbols)]),
  
    format('Reading sections~n',[]),
  	read_sections(File,Sections),
    maplist(extract_section(File),Sections),
    format('Decoding sections~n',[]),
    decode_sections(File,Sections,Dir),
    format('Calling souffle~n',[]),
    call_souffle(Dir),
    format('Collecting results and printing~n',[]),
    collect_results(Dir,_Results),
    maplist(assert,Sections),
    pretty_print_results,
    print_stats.
   

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% predicates for reading elf information
read_symbols(File,Symbols_final):-
    atom_concat(File,'.symbols',File2),
    read_terms_from_filename(File2,Symbols-[]),
    maplist(\Symbol^Symbol2^(
		Symbol=symbol(Address,N,Type,Scope,Name),
		hex_to_dec(Address,Address_dec),
		maplist(atom_string,[Type,Scope,Name],[TypeStr,ScopeStr,NameStr]),
		Symbol2=symbol(Address_dec,N,TypeStr,ScopeStr,NameStr)
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

section_of_interest(section('.eh_frame',_Type,_Address)).
section_of_interest(section('.text',_Type,_Address)).
section_of_interest(section('.plt',_Type,_Address)).
section_of_interest(section('.plt.got',_Type,_Address)).
section_of_interest(section('.init',_Type,_Address)).
section_of_interest(section('.fini',_Type,_Address)).
%section_of_interest(section('.rodata',_Type,_Address)).

extract_section(File,section(Name,_Type,_Address)):-
    %objcopy -O binary --only-section=.text $1 $1.text
    atomic_list_concat(['objcopy -O binary --only-section=',Name,' ',File,' ',File,Name],Cmd),
    shell(Cmd).

decode_sections(File,Sections,Dir):-
	 foldl(collect_section_addresses(File),Sections,([],[]),(Sect_names,Sect_addr)),
	 atomic_list_concat(Sect_names,Section_chain),
	 atomic_list_concat(Sect_addr,Addr_chain),
	 atomic_list_concat(['./souffle_disasm ',Section_chain,' ',Addr_chain,' --dir ',Dir,'/'],Cmd),
	 shell(Cmd).
   
collect_section_addresses(File,section(Name,_,Address),(Acc_sec,Acc_addr),(Acc_sec2,Acc_addr2)):-
	Acc_sec2=[' --sect ',File,Name|Acc_sec],
	Acc_addr2=[' --addr ',Address|Acc_addr].
	
/* 



decode_sections
    % extract the instructions at all possible addresses
    (Name='.rodata'->
    	atomic_list_concat(['./souffle_disasm  ',File,Name,' -address=',Address,' -data > ',File,Name,'.dec'],Cmd2)
    	;
    	atomic_list_concat(['./souffle_disasm  ',File,Name,' -address=',Address],Cmd2)
    	),
    shell(Cmd2).
*/
    %./x64show  -f=$1.text -address=0x$offset_text -omit-prefix > $1.dec
    %atomic_list_concat(['./x64show  -f=',File,Name,' -address=',Address,' -omit-prefix -asm > ',File,Name,'.incomplete.dec'],Cmd3),
    %shell(Cmd3).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% basic read and writing

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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%	
% Save the facts and the rules in different formats

save_db(souffle,Dir,Terms):-
	foldl(write_fact_list(Dir),Terms,[],_).

write_fact_list(Dir,fact_list(Name,List),Open_files,Open_files2):-
	get_fact_file_name(Dir,Name,File),
	(member(Name,Open_files)->
		open(File,append,S)
		;
		open(File,write,S),
		Open_files2=[Name|Open_files]	
    ),
    csv_write_stream(S, List, [functor(Name), separator(0'\t)]),
    close(S).


get_fact_file_name(Dir,Name,Path):-
	atom_concat(Name,'.facts',NameExt),
	directory_file_path(Dir,NameExt,Path).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
call_souffle(Dir):-
	%souffle souffle_rules.pl -I ../examples/bzip/
	atomic_list_concat(['souffle souffle_rules.pl -j 4 -F ',Dir,' -D ',Dir],Cmd),
	time(shell(Cmd)).
	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
result_descriptors([
	res(valid4sure,2,'.csv'),
	res(maybe_valid2,1,'.csv'),
	res(function_symbol,2,'.csv'),
	res(block_start,1,'.csv'),
	res(instruction,6,'.facts'),
	res(op_regdirect,2,'.facts'),
	res(op_immediate,2,'.facts'),
	res(op_indirect,7,'.facts')
	]).

:-dynamic maybe_valid2/1.
:-dynamic valid4sure/2.
:-dynamic function_symbol/2.
:-dynamic block_start/1.

:-dynamic section/3.
:-dynamic instruction/6.
:-dynamic op_regdirect/2.
:-dynamic op_immediate/2.
:-dynamic op_indirect/7.

collect_results(Dir,results(Results)):-
	result_descriptors(Descriptors),
	maplist(collect_result(Dir),Descriptors,Results).

collect_result(Dir,res(Name,Arity,Ending),Result):-
	atom_concat(Name,Ending,Name_file),
	directory_file_path(Dir,Name_file,Path),
	csv_read_file(Path, Result, [functor(Name), arity(Arity),separator(0'\t)]),
	maplist(assertz,Result).
	

get_op(0,none):-!.
get_op(N,reg(Name)):-
	op_regdirect(N,Name),!.
get_op(N,immediate(Immediate)):-
	op_immediate(N,Immediate),!.
get_op(N,indirect(Reg1,Reg2,Reg3,A,B,C)):-
	op_indirect(N,Reg1,Reg2,Reg3,A,B,C),!.
	
pretty_print_results:-
	findall(Instruction,
	(
		instruction(EA,Size,Name,Opc1,Opc2,Opc3),
		get_op(Opc1,Op1),
		get_op(Opc2,Op2),
		get_op(Opc3,Op3),
		Instruction=instruction(EA,Size,Name,Op1,Op2,Op3)
	),Instructions),
	maplist(pp_instruction, Instructions).
		


pp_instruction(instruction(EA,_Size,OpCode,Op1,Op2,Op3)):-
	(section(Section_name,_,EA)->
		format('Section ~p:~n',[Section_name])
		;
		true),
	maybe_valid2(EA),!,
	exclude(\Op^(Op=none),[Op1,Op2,Op3],Ops),
	maplist(pp_op,Ops,Pretty_ops),
	convlist(get_comment,Ops,Comments),
	reverse(Pretty_ops,Pretty_ops_rev),

	(
		function_symbol(EA,Name),
		format('Function ~p:~n',[Name])
	;
	 	block_start(EA),
	  	format('  Label ~16R:~n',[EA]) 
	;
		true
	),!,
	
	(valid4sure(EA,_Parent)->
		format('         ~16R:   ~p',[EA,OpCode])
		;
		format('~p        ~16R:   ~p',['?',EA,OpCode])
	),
	maplist(print_with_space,Pretty_ops_rev),
	% print the names of the immediates if they are functions
	(Comments\=[]->
		format('          # ',[]),
		maplist(print_with_space,Comments)
		;true
	),
	nl.
		 
pp_instruction(_).


print_with_space(Op+Offset):-!,
	format(' [~p+~16R] ',[Op,Offset]). 
print_with_space([Op+Offset]):-!,
	format(' [~p+~16R] ',[Op,Offset]). 

print_with_space(Op):-
	number(Op),!,
	format(' ~16R ',[Op]). 
print_with_space(Op):-
	format(' ~p ',Op). 
		
get_comment(Op,Name):-
	Op=immediate(Num),
	Num\=0,
	function_symbol(Num,Name).


	
pp_op(reg(Name),Name).
pp_op(immediate(Num),Num).

pp_op(indirect('NullSReg',Reg,'NullReg64',1,0,_),[Reg]). 	 
pp_op(indirect('NullSReg',Reg,'NullReg64',1,Offset,_),[Reg+Offset]).

%pp_op(indirect(nullsreg,Reg,nullreg64,1,Offset,_)),[Reg+Offset]).


pp_op(Else,Else).	 



print_stats:-
	format('~n~nResult statistics:~n',[]),
	result_descriptors(Descriptors),
	maplist(print_descriptor_stats,Descriptors).

print_descriptor_stats(res(Name,Arity,_)):-
	functor(Head,Name,Arity),
	findall(Head,Head,Results),
	length(Results,N),
	format(' Number of ~p: ~p~n',[Name,N]).

	 	  	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% auxiliary predicates
hex_to_dec(Hex,Dec):-
    hex_bytes(Hex,Bytes),
    byte_list_to_num(Bytes,0,Dec).

byte_list_to_num([],Accum,Accum).
byte_list_to_num([Byte|Bytes],Accum,Dec):-
    Accum2 is Byte+256*Accum,
    byte_list_to_num(Bytes,Accum2,Dec).


