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
    format('Reading sections~n',[]),
    read_sections(File,Sections),
    trace,
    maplist(extract_section(File),Sections),
    
    format('Decoding sections~n',[]),
    % we are going to move all this to the C++
    
 %   init_operand_codes,
 %   maplist(decode_section(File),Sections,Decoded_sections),!,
 %   format('Generating facts~n',[]),
    collect_datalog_program([decoded_section(symbols,Symbols)],Dl_program-[]),
 %  % atom_concat(File,'.dl',File3),
    format('Storing facts~n',[]),
    file_directory_name(File, Dir),
    save_db(souffle,Dir,Dl_program),
    format('Calling souffle~n',[]),
    call_souffle(Dir),
    format('Collecting results~n',[]),
    collect_results(Dir,_Results),
    pretty_print_results(Decoded_sections),
    print_stats.
   
 %   atom_concat(File,'.bdd',File4),
 %   save_db(bddbddb,File4,Dl_program).


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

%section_of_interest(section('.eh_frame',_Type,_Address)).
section_of_interest(section('.text',_Type,_Address)).
%section_of_interest(section('.plt',_Type,_Address)).
%section_of_interest(section('.plt.got',_Type,_Address)).
%section_of_interest(section('.init',_Type,_Address)).
%section_of_interest(section('.fini',_Type,_Address)).
%section_of_interest(section('.rodata',_Type,_Address)).

extract_section(File,section(Name,_Type,Address)):-
    %objcopy -O binary --only-section=.text $1 $1.text
    atomic_list_concat(['objcopy -O binary --only-section=',Name,' ',File,' ',File,Name],Cmd),
    shell(Cmd),
    % extract the instructions at all possible addresses
    (Name='.rodata'->
    	atomic_list_concat(['./souffle_disasm  ',File,Name,' -address=',Address,' -data > ',File,Name,'.dec'],Cmd2)
    	;
    	atomic_list_concat(['./souffle_disasm  ',File,Name,' -address=',Address],Cmd2)
    	),
    shell(Cmd2).
    %./x64show  -f=$1.text -address=0x$offset_text -omit-prefix > $1.dec
    %atomic_list_concat(['./x64show  -f=',File,Name,' -address=',Address,' -omit-prefix -asm > ',File,Name,'.incomplete.dec'],Cmd3),
    %shell(Cmd3).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

decode_section(File,section(Name,_,_Address),decoded_section(Name,Decoded_terms)):-
    atomic_list_concat([File,Name,'.dec'],SectionFile),
    read_terms_from_filename(SectionFile,Terms-[]),
    decode_final(Terms,Decoded_terms-Decoded_terms).

decode_final([],_Head-[]).
decode_final([X|Xs],Head-[X2|Tail2]):-
	decode(X,X2),!,extract_operands(X2,X3),
	decode_final(Xs,Head-Tail2).
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
    
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% decodification of instructions into a uniform format
decode(threeop128_128_8(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,Op1,Op2,Op3)):-!.
decode(threeop32_64_8(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,Op1,Op2,Op3)):-!.
decode(threeop32_32_32(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,Op1,Op2,Op3)):-!.
decode(threeop32_32_8(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,Op1,Op2,Op3)):-!.
decode(threeop64_64_32(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,Op1,Op2,Op3)):-!.
decode(threeop64_64_8(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,Op1,Op2,Op3)):-!.


decode(twoop128(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.

decode(twoop32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop64(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.


decode(oneop64(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,Op1,none,none)):-!.
decode(oneop32(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,Op1,none,none)):-!.
decode(oneop16(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,Op1,none,none)):-!.
decode(oneop8(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,Op1,none,none)):-!.
decode(oneop80(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,Op1,none,none)):-!.

decode(twoop128_64(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop128_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop128_16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop128_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.

decode(twoop64_128(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop64_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop64_16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop64_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.

decode(twoop32_128(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop32_64(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop32_48(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop32_16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop32_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.

decode(twoop16_64(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop16_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop16_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.

decode(twoop8_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.
decode(twoop8_16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,Op1,Op2,none)):-!.

decode(zeroop(EA,Size,_,OpCode),instruction(EA,Size,OpCode,none,none,none)):-!.
decode(ret(EA,Size,_,_),instruction(EA,Size,ret,none,none,none)):-!.
decode(iret64(EA,Size,_),instruction(EA,Size,iret64,none,none,none)):-!.
decode(iret32(EA,Size,_),instruction(EA,Size,iret32,none,none,none)):-!.
decode(iret16(EA,Size,_),instruction(EA,Size,iret16,none,none,none)):-!.

decode(oneopfloat(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,Op1,none,none)).

decode(lea64(EA,Size,_,Op1,Op2),instruction(EA,Size,lea,Op1,Op2,none)):-!.
decode(lea32(EA,Size,_,Op1,Op2),instruction(EA,Size,lea,Op1,Op2,none)):-!.

decode(fldenv(EA,Size,_,Op1),instruction(EA,Size,fldenv,Op1,none,none)):-!.
decode(fnstenv(EA,Size,_,Op1),instruction(EA,Size,fnstenv,Op1,none,none)):-!.

decode(farret(EA,Size,_,Op1),instruction(EA,Size,farret,Op1,none,none)):-!.
decode(fnsave(EA,Size,_,Op1),instruction(EA,Size,fnsave,Op1,none,none)):-!.
decode(frstor(EA,Size,_,Op1),instruction(EA,Size,frstor,Op1,none,none)):-!.


decode(farindirect32(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,Op1,none,none)):-!.

decode(invalid(EA),invalid(EA)):-!.

decode(Other,none):-format('Unrecognized instruction ~p~n',[Other]),halt.


% the operands are not flat so we extract them into different predicates
% regdirect/2 immediate/2 or indirect/8 or none
extract_operands(instruction(EA,Size,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,Op_code1,Op_code2,Op_code3)):-
	maplist(get_op_code,[Op1,Op2,Op3],[Op_code1,Op_code2,Op_code3]).


:-dynamic op_code/2.
:-dynamic op_code_counter/1.

init_operand_codes:-
	retractall(op_code_counter(_)),
	retractall(op_code(_,_)),
	assert(op_code_counter(1)),
	assert(op_code(none,0)).
	
get_op_code(Op,Op_code):-
	transform_operand(Op,Op_tr),
	get_op_code_1(Op_tr,Op_code).

get_op_code_1(Op,Op_code):-
	op_code(Op,Op_code),!.

get_op_code_1(Op,N):-
	retract(op_code_counter(N)),
	assertz(op_code(Op,N)),
	N1 is N+1,
	assert(op_code_counter(N1)).
	
	
transform_operand(none,none):-!.
transform_operand(regdirect32(Name),regdirect(Name,32)):-!.
transform_operand(regdirect64(Name),regdirect(Name,64)):-!.
transform_operand(regdirect16(Name),regdirect(Name,16)):-!.
transform_operand(regdirect8(Name),regdirect(Name,8)):-!.

transform_operand(immediate64(Num,_,_),immediate(Num,64)):-!.
transform_operand(immediate32(Num,_,_),immediate(Num,32)):-!.
transform_operand(immediate16(Num,_,_),immediate(Num,16)):-!. 
transform_operand(immediate8(Num,_,_),immediate(Num,8)):-!. 	 

transform_operand(indirect64(addr64(Reg1,Reg2,Reg3,Multiplier,Offset,NoIdea,NoIdea2)),
				  indirect(Reg1,Reg2,Reg3,Multiplier,Offset,NoIdea,NoIdea2,64)):-!.
				  
transform_operand(indirect32(addr64(Reg1,Reg2,Reg3,Multiplier,Offset,NoIdea,NoIdea2)),
				  indirect(Reg1,Reg2,Reg3,Multiplier,Offset,NoIdea,NoIdea2,32)):-!.
				  
transform_operand(indirect16(addr64(Reg1,Reg2,Reg3,Multiplier,Offset,NoIdea,NoIdea2)),
				  indirect(Reg1,Reg2,Reg3,Multiplier,Offset,NoIdea,NoIdea2,16)):-!.
				  
transform_operand(indirect8(addr64(Reg1,Reg2,Reg3,Multiplier,Offset,NoIdea,NoIdea2)),
				  indirect(Reg1,Reg2,Reg3,Multiplier,Offset,NoIdea,NoIdea2,8)):-!.	  				  				  


transform_operand(Other,_):-format('Unrecognized operand ~p~n',[Other]),halt.
	

	
	
	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% collect facts from the instruction list

collect_datalog_program(Decoded_sections,Dl_program-Dl_tail2):-
    collect_all_facts(Decoded_sections,Dl_program-Dl_tail2).

collect_all_facts([],Dl_tail-Dl_tail).


collect_all_facts([Decoded_section|More_terms],Dl_program-Dl_tail2):-
    collect_facts(Decoded_section,Dl_program-Dl_tail),
    collect_all_facts(More_terms,Dl_tail-Dl_tail2).

collect_facts(decoded_section(_Name,Instructions),Facts-Tail):-
    convlist_final(collect_symbols,Instructions,Symbols),
    convlist_final(collect_possible_target,Instructions,Possible_tgs),
    convlist_final(collect_next,Instructions,Targets),
    convlist_final(collect_direct_jump,Instructions,Jumps),  
    convlist_final(collect_inconditional_jump,Instructions,Incond_Jumps),
    convlist_final(collect_direct_call,Instructions,Calls),
    convlist_final(collect_invalid,Instructions,Invalids),
    convlist_final(collect_maybe_valid,Instructions,Valids),
    convlist_final(collect_return,Instructions,Returns),
    Facts=[
	fact_list(symbol,Symbols),
	fact_list(possible_target,Possible_tgs),
	fact_list(next,Targets),
	fact_list(direct_jump,Jumps),
	fact_list(inconditional_jump,Incond_Jumps),
	fact_list(direct_call,Calls),
	fact_list(invalid,Invalids),
	fact_list(maybe_valid,Valids),
	fact_list(return,Returns)| Tail].


convlist_final(Pred,List,Res):-
	convlist_final_aux(List,Pred,[],Res).

convlist_final_aux([],_Pred,Accum,Accum).
convlist_final_aux([X|Xs],Pred,Accum,Res):-
	call(Pred,X,X2),!,
	convlist_final_aux(Xs,Pred,[X2|Accum],Res).
convlist_final_aux([_X|Xs],Pred,Accum,Res):-
	convlist_final_aux(Xs,Pred,Accum,Res).	
	
	
collect_possible_target(instruction(_EA,_Size,_OpCode,Operands),possible_target(Val)):-
	once(member(immediate32(Val,_,_),Operands)).
collect_possible_target(instruction(_EA,_Size,_OpCode,Operands),possible_target(Val)):-
	once(member(immediate64(Val,_,_),Operands)).
		
collect_symbols(symbol(Address,N,Type,Scope,Name),symbol(Address,N,Type,Scope,Name)).

collect_next(instruction(EA,Size,_OpCode,_),next(EA,EA2)):-
    EA2 #= EA+Size.


collect_direct_jump(instruction(EA,_Size,Opcode,[immediate64(Dest,_,_)]),direct_jump(EA,Dest)):-
    member(Opcode,[jmp,jnz,jz,jge,jna]).
    
collect_inconditional_jump(instruction(EA,_Size,jmp,[_]),inconditional_jump(EA)).
    
    
collect_direct_call(instruction(EA,_Size,call,[immediate64(Dest,_,_)]),direct_call(EA,Dest)).

collect_maybe_valid(instruction(EA,_,_,_),maybe_valid(EA)).


collect_invalid(invalid(EA),invalid(EA)).

collect_return(instruction(EA,_Size,ret,[]),return(EA)).

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
	res(valid4sure,2),
	res(maybe_valid2,1),
	res(function_symbol,2),
	res(block_start,1)
	]).

:-dynamic maybe_valid2/1.
:-dynamic valid4sure/2.
:-dynamic function_symbol/2.
:-dynamic block_start/1.


collect_results(Dir,results(Results)):-
	result_descriptors(Descriptors),
	maplist(collect_result(Dir),Descriptors,Results).

collect_result(Dir,res(Name,Arity),Result):-
	atom_concat(Name,'.csv',Name_file),
	directory_file_path(Dir,Name_file,Path),
	csv_read_file(Path, Result, [functor(Name), arity(Arity),separator(0'\t)]),
	maplist(assert,Result).
	


pretty_print_results(Decoded_sections):-
	maplist(pretty_print_section_results,Decoded_sections).

pretty_print_section_results(decoded_section(Name,Instructions)):-
	format('~n~nSection: ~p~n',[Name]),
	maplist(pp_instruction,Instructions).

pp_instruction(instruction(EA,_Size,OpCode,Ops)):-
	maplist(pp_op,Ops,Pretty_ops),
	convlist_final(get_comment,Ops,Comments),
	reverse(Pretty_ops,Pretty_ops_rev),
	maybe_valid2(EA),!,
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
	(
	Op=immediate64(Num,_,_)
	;
	Op=immediate32(Num,_,_)
	;
	Op=immediate16(Num,_,_)
	;
	Op=immediate8(Num,_,_)
	),
	Num\=0,
	function_symbol(Num,Name).
	
pp_op(regdirect32(Name),Name).
pp_op(regdirect64(Name),Name).
pp_op(regdirect16(Name),Name).
pp_op(regdirect8(Name),Name).

pp_op(immediate64(Num,_,_),Num).
pp_op(immediate32(Num,_,_),Num).
pp_op(immediate16(Num,_,_),Num).	  
pp_op(immediate8(Num,_,_),Num).	  	 

pp_op(indirect64(addr64(nullsreg,Reg,nullreg64,1,0,0,0)),[Reg]).
pp_op(indirect32(addr64(nullsreg,Reg,nullreg64,1,0,0,0)),[Reg]).
pp_op(indirect16(addr64(nullsreg,Reg,nullreg64,1,0,0,0)),[Reg]).
pp_op(indirect8(addr64(nullsreg,Reg,nullreg64,1,0,0,0)),[Reg]).

pp_op(indirect64(addr64(nullsreg,Reg,nullreg64,1,Offset,_,_)),[Reg+Offset]).
pp_op(indirect32(addr64(nullsreg,Reg,nullreg64,1,Offset,_,_)),[Reg+Offset]).
pp_op(indirect16(addr64(nullsreg,Reg,nullreg64,1,Offset,_,_)),[Reg+Offset]).
pp_op(indirect8(addr64(nullsreg,Reg,nullreg64,1,Offset,_,_)),[Reg+Offset]).


pp_op(addr64(nullsreg,Reg,nullreg64,1,Offset,_,_),Reg+Offset).

pp_op(Else,Else).	 



print_stats:-
	format('~n~nResult statistics:~n',[]),
	result_descriptors(Descriptors),
	maplist(print_descriptor_stats,Descriptors).

print_descriptor_stats(res(Name,Arity)):-
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


