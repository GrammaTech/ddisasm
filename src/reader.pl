:-module(reader,[read_binary/1]).

:-use_module(library(lambda)).
:-use_module(library(clpfd)).

analysis_file('souffle_main.pl').

read_binary([File|_Args]):-
	set_prolog_flag(print_write_options,[quoted(false)]),
	format('Decoding binary~n',[]),
	file_directory_name(File, Dir),
    decode_sections(File,Dir),
    format('Calling souffle~n',[]),
    call_souffle(Dir),
    format('Collecting results and printing~n',[]),
    collect_results(Dir,_Results),
    pretty_print_results,
    print_stats.
   
decode_sections(File,Dir):-
	Sections=[
		'.eh_frame',
		'.text',
		'.plt',
		'.plt.got',
		'.init',
		'.fini'],
	 Data_sections=['.data','.rodata'],
	 foldl(collect_section_args(' --sect '),Sections,[],Sect_args),
	 foldl(collect_section_args(' --data_sect '),Data_sections,[],Data_sect_args),
	 atomic_list_concat(Sect_args,Section_chain),
	 atomic_list_concat(Data_sect_args,Data_section_chain),
	 atomic_list_concat(['./souffle_disasm ',' --file ',File,' --dir ',Dir,'/',Section_chain,Data_section_chain],Cmd),
	 format('cmd: ~p~n',[Cmd]),
	 shell(Cmd).
   
collect_section_args(Arg,Name,Acc_sec,Acc_sec2):-
	Acc_sec2=[Arg,Name|Acc_sec].
	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
call_souffle(Dir):-
	%souffle souffle_rules.pl -I ../examples/bzip/
	atomic_list_concat(['souffle souffle_rules.dl -j 4 -F ',Dir,' -D ',Dir],Cmd),
	time(shell(Cmd)).
	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
result_descriptors([
	res(valid4sure,2,'.csv'),
	res(maybe_valid2,1,'.csv'),
	res(function_symbol,2,'.csv'),
	res(section,3,'.facts'),
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


