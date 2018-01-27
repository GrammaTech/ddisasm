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
    collect_datalog_program([decoded_section(Symbols)|Decoded_sections],Dl_program-[]),
   % atom_concat(File,'.dl',File3),
    save_db(souffle,File,Dl_program).
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

extract_section(File,section(Name,_Type,Address)):-
    %objcopy -O binary --only-section=.text $1 $1.text
    atomic_list_concat(['objcopy -O binary --only-section=',Name,' ',File,' ',File,Name],Cmd),
    shell(Cmd),
    % extract the instructions at all possible addresses
    atomic_list_concat(['./souffle_disasm  ',File,Name,' -address=',Address,'  > ',File,Name,'.dec'],Cmd2),
    shell(Cmd2),
    %./x64show  -f=$1.text -address=0x$offset_text -omit-prefix > $1.dec
    atomic_list_concat(['./x64show  -f=',File,Name,' -address=',Address,' -omit-prefix > ',File,Name,'.incomplete.dec'],Cmd3),
    shell(Cmd3).

decode_section(File,section(Name,_,_Address),decoded_section(Decoded_terms)):-
    atomic_list_concat([File,Name,'.dec'],SectionFile),
    read_terms_from_filename(SectionFile,Terms-[]),
    maplist(decode,Terms,Decoded_terms).

%for now we only get the .text section
section_of_interest(section('.text',_Type,_Address)).
section_of_interest(section('.plt',_Type,_Address)).
section_of_interest(section('.plt.got',_Type,_Address)).
section_of_interest(section('.init',_Type,_Address)).
section_of_interest(section('.fini',_Type,_Address)).
%section_of_interest(section('.eh_frame',_Type,_Address)).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% decodification of instructions into a uniform format

decode(threeop32_32_32(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,[Op1,Op2,Op3])):-!.
decode(threeop32_32_8(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,[Op1,Op2,Op3])):-!.
decode(threeop64_64_32(EA,Size,_,OpCode,Op1,Op2,Op3),instruction(EA,Size,OpCode,[Op1,Op2,Op3])):-!.

decode(twoop128(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(twoop32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop64(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.


decode(oneop64(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])):-!.
decode(oneop32(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])):-!.
decode(oneop16(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])):-!.
decode(oneop8(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])):-!.
decode(oneop80(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])):-!.

decode(twoop128_64(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop128_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(twoop64_128(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop64_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop64_16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop64_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.


decode(twoop32_16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop32_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(twoop16_64(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop16_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop16_8(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(twoop8_32(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.
decode(twoop8_16(EA,Size,_,OpCode,Op1,Op2),instruction(EA,Size,OpCode,[Op1,Op2])):-!.

decode(zeroop(EA,Size,_,OpCode),instruction(EA,Size,OpCode,[])):-!.
decode(ret(EA,Size,_,_),instruction(EA,Size,ret,[])):-!.
decode(iret32(EA,Size,_),instruction(EA,Size,iret32,[])):-!.

decode(oneopfloat(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])).

decode(lea64(EA,Size,_,Op1,Op2),instruction(EA,Size,lea,[Op1,Op2])):-!.
decode(lea32(EA,Size,_,Op1,Op2),instruction(EA,Size,lea,[Op1,Op2])):-!.

decode(fldenv(EA,Size,_,Op1),instruction(EA,Size,fldenv,[Op1])):-!.
decode(fnstenv(EA,Size,_,Op1),instruction(EA,Size,fnstenv,[Op1])):-!.

decode(farret(EA,Size,_,Op1),instruction(EA,Size,farret,[Op1])):-!.
decode(fnsave(EA,Size,_,Op1),instruction(EA,Size,fnsave,[Op1])):-!.
decode(frstor(EA,Size,_,Op1),instruction(EA,Size,frstor,[Op1])):-!.


decode(farindirect32(EA,Size,_,OpCode,Op1),instruction(EA,Size,OpCode,[Op1])):-!.

decode(invalid(EA),invalid(EA)):-!.

decode(Other,none):-format('Unrecognized instruction ~p~n',[Other]),fail.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% collect facts from the instruction list

collect_datalog_program(Decoded_sections,Dl_program-Dl_tail2):-
    collect_all_facts(Decoded_sections,Dl_program-Dl_tail2).

collect_all_facts([],Dl_tail-Dl_tail).


collect_all_facts([Decoded_section|More_terms],Dl_program-Dl_tail2):-
    collect_facts(Decoded_section,Dl_program-Dl_tail),
    collect_all_facts(More_terms,Dl_tail-Dl_tail2).

collect_facts(decoded_section(Instructions),Facts-Tail):-
    convlist(collect_symbols,Instructions,Symbols),
    convlist(collect_possible_target,Instructions,Possible_tgs),
    convlist(collect_next,Instructions,Targets),
    convlist(collect_direct_jump,Instructions,Jumps),  
    convlist(collect_inconditional_jump,Instructions,Incond_Jumps),
    convlist(collect_direct_call,Instructions,Calls),
    convlist(collect_invalid,Instructions,Invalids),
    convlist(collect_maybe_valid,Instructions,Valids),
    convlist(collect_return,Instructions,Returns),
    convlist(collect_instruction_text,Instructions,Text),
    Facts=[
	fact_list(symbol,Symbols),
	fact_list(possible_target,Possible_tgs),
	fact_list(next,Targets),
	fact_list(direct_jump,Jumps),
	fact_list(inconditional_jump,Incond_Jumps),
	fact_list(direct_call,Calls),
	fact_list(invalid,Invalids),
	fact_list(maybe_valid,Valids),
	fact_list(instruction_text,Text),
	fact_list(return,Returns)| Tail].


collect_possible_target(instruction(_EA,_Size,_OpCode,Operands),possible_target(Val)):-
	once(member(immediate32(Val,_,_),Operands)).
collect_possible_target(instruction(_EA,_Size,_OpCode,Operands),possible_target(Val)):-
	once(member(immediate64(Val,_,_),Operands)).
		
collect_symbols(symbol(Address,N,Type,Scope,Name),symbol(Address,N,Type,Scope,Name)).

collect_next(instruction(EA,Size,_OpCode,_),next(EA,EA2)):-
    EA2 #= EA+Size.
%for now we will do this later	using the other prediacates
%	OpCode\=ret,
%	OpCode\=jmp,
%	OpCode\=halt,

collect_direct_jump(instruction(EA,_Size,Opcode,[immediate64(Dest,_,_)]),direct_jump(EA,Dest)):-
    member(Opcode,[jmp,jnz,jz,jge,jna]).
    
collect_inconditional_jump(instruction(EA,_Size,jmp,[_]),inconditional_jump(EA)).
    
    
collect_direct_call(instruction(EA,_Size,call,[immediate64(Dest,_,_)]),direct_call(EA,Dest)).

collect_maybe_valid(instruction(EA,_,_,_),maybe_valid(EA)).

collect_instruction_text(instruction(EA,_,Opcode,Ops),instruction_text(EA,Text)):-
	pretty_print_instruction(Opcode,Ops,Text).

pretty_print_instruction(Opcode,Ops,Text):-
	Term=..[Opcode|Ops],
	term_string(Term,Text).

collect_invalid(invalid(EA),invalid(EA)).

collect_return(instruction(EA,_Size,ret,[]),return(EA)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%	
% Save the facts and the rules in different formats

save_db(souffle,File,Terms):-
	file_directory_name(File, Dir),
	foldl(write_fact_list(Dir),Terms,[],_).

write_fact_list(Dir,fact_list(Name,List),Open_files,Open_files2):-
	get_fact_file_name(Dir,Name,File),
	(member(Name,Open_files)->
		open(File,append,S)
		;
		open(File,write,S),
		Open_files2=[Name|Open_files]	
    ),
    maplist(\Term^write_term(S,Term,[fullstop(true),nl(true),quoted(true)]),List),
    close(S).


get_fact_file_name(Dir,Name,Path):-
	atom_concat(Name,'.facts',NameExt),
	directory_file_path(Dir,NameExt,Path).
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


