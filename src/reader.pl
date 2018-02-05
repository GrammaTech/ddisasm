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
	%	'.eh_frame',
		'.text',
	%	'.plt',
	%	'.plt.got',
		'.init',
		'.fini'],
	Data_sections=[
	    '.got',
	   % '.got.plt',
	    '.data',
	    '.rodata'],
	 foldl(collect_section_args(' --sect '),Sections,[],Sect_args),
	 foldl(collect_section_args(' --data_sect '),Data_sections,[],Data_sect_args),
	 atomic_list_concat(Sect_args,Section_chain),
	 atomic_list_concat(Data_sect_args,Data_section_chain),
	 atomic_list_concat(['./souffle_disasm ',' --file ',File,
			     ' --dir ',Dir,'/',Section_chain,Data_section_chain],Cmd),
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
	res(section,3,'.facts'),
	res(instruction,6,'.facts'),
	res(op_regdirect,2,'.facts'),
	res(op_immediate,2,'.facts'),
	res(op_indirect,7,'.facts'),

	res(direct_jump,2,'.csv'),	
	res(reg_computed_jump,1,'.csv'),
	res(indirect_computed_jump,1,'.csv'),
	res(pc_relative_jump,2,'.csv'),
	res(direct_call,2,'.csv'),


	res(likely_ea2,2,'.csv'),
	res(possible_ea2,1,'.csv'),
	res(function_symbol,2,'.csv'),
	res(block_start,1,'.csv'),
	res(conflict3,2,'.csv'),

	res(likely_ea3,2,'.csv')
	]).

:-dynamic section/3.
:-dynamic instruction/6.
:-dynamic op_regdirect/2.
:-dynamic op_immediate/2.
:-dynamic op_indirect/7.

:-dynamic direct_jump/2.
:-dynamic reg_computed_jump/1.
:-dynamic indirect_computed_jump/1.
:-dynamic pc_relative_jump/2.

:-dynamic likely_ea2/2.
:-dynamic possible_ea2/1.
:-dynamic function_symbol/2.
:-dynamic block_start/1.
:-dynamic conflict3/2.

:-dynamic likely_ea3/2.

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
	(likely_ea3(EA,_)
         %i'm feeling lucky
	 %;possible_ea2(EA)
	),!,
	exclude(\Op^(Op=none),[Op1,Op2,Op3],Ops),
	maplist(pp_op,Ops,Pretty_ops),
	%useful info
	convlist(get_comment,Ops,Op_comments),
	get_ea_comments(EA,Comments),
	append(Comments,Op_comments,All_comments),
	reverse(Pretty_ops,Pretty_ops_rev),

	(
	    (
		(function_symbol(EA,Name),Maybe='')
	     ;
	     (member(is_called,Comments),Name='unknown',Maybe='(maybe)')
	    ),
	    
	    format(';----------------------------------- ~n',[]),
	    format('   Function~p ~p:~n',[Maybe,Name]),
	    format(';----------------------------------- ~n',[])
	 ;
	 block_start(EA),
	 format('  Label ~16R:~n',[EA]) 
	 ;
	 true
	),!,	
	format('         ~16R:   ~p',[EA,OpCode]), 
	maplist(print_with_space,Pretty_ops_rev),
	% print the names of the immediates if they are functions
	(All_comments\=[]->
		format('          # ',[]),
		maplist(print_with_space,All_comments)
		;true
	),
	nl.
		 
pp_instruction(_).


print_with_space(Op):-
	format(' ~p ',[Op]). 
		

get_ea_comments(EA,Comments):-
    setof(Comment,
	    ea_comment(EA,Comment),
	    Comments),!.
get_ea_comments(_EA,[]).

ea_comment(EA,is_called):-
    direct_call(_,EA).

ea_comment(EA,conflict_with(EA2)):-
    conflict3(EA2,EA).
ea_comment(EA,conflict_with(EA2)):-
    conflict3(EA,EA2).

ea_comment(EA,not_in_block):-
    \+likely_ea3(EA,_).

ea_comment(EA,is_jumped_to_from(Str_or)):-
    direct_jump(Or,EA),
    format(string(Str_or),'~16R',[Or]).

ea_comment(EA,reg_jump):-
    reg_computed_jump(EA).
ea_comment(EA,indirect_jump):-
    indirect_computed_jump(EA).

ea_comment(EA,pc_relative_jump(Dest)):-
    pc_relative_jump(EA,Dest).

get_comment(Op,Name):-
	Op=immediate(Num),
	Num\=0,
	function_symbol(Num,Name).


	
pp_op(reg(Name),Name).
pp_op(immediate(Num),Num_hex):-
      format(string(Num_hex),'~16R',[Num]).

pp_op(indirect('NullSReg',Reg,'NullReg64',1,0,_),[Reg]). 	 
pp_op(indirect('NullSReg',Reg,'NullReg64',1,Offset,_),[Reg+Offset_hex]):-
       format(string(Offset_hex),'~16R',[Offset]).

pp_op(indirect('NullSReg','NullReg64',Reg_index,Mult,Offset,_),[Offset_hex+Reg_index*Mult]):-
    format(string(Offset_hex),'~16R',[Offset]).
pp_op(indirect('NullSReg',Reg,Reg_index,Mult,0,_),[Reg+Reg_index*Mult]).
pp_op(indirect('NullSReg',Reg,Reg_index,Mult,Offset,_),[Reg+Offset_hex+Reg_index*Mult]):-
       format(string(Offset_hex),'~16R',[Offset]).


pp_op(indirect(SReg,'NullReg64','NullReg64',1,Offset,_),[SReg:Offset_hex]):-
       format(string(Offset_hex),'~16R',[Offset]).


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


