:-module(disasm_driver,[disasm_binary/1]).

:-use_module(library(lambda)).
:-use_module(library(clpfd)).

sections([
		%	'.eh_frame',
		'.text',
		'.plt',
		'.init',
		'.fini']).
data_sections([
		     '.got',
		     '.plt.got',
		     % '.got.plt',
		     '.data',
		     '.rodata']).

analysis_file('souffle_main.pl').

disasm_binary([File|Args]):-
    maplist(save_option,Args),
    set_prolog_flag(print_write_options,[quoted(false)]),
    format('Decoding binary~n',[]),
    file_directory_name(File, Dir),
    atom_concat(Dir,'/dl_files',Dir2),
    (\+exists_directory(Dir2)->
	 make_directory(Dir2);true),
    decode_sections(File,Dir2),
    format('Calling souffle~n',[]),
    call_souffle(Dir2),
    (option(no_print)->
	 true
     ;
     format('Collecting results and printing~n',[]),
     collect_results(Dir2,_Results),
     generate_hints(Dir),
     pretty_print_results,
     print_stats
    ).

:-dynamic option/1.
save_option(Arg):-
    assert(option(Arg)).

decode_sections(File,Dir):-
    sections(Sections),
    data_sections(Data_sections),
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
    atomic_list_concat(['souffle ../src/souffle_rules.dl  -F ',Dir,' -D ',Dir,' -p ',Dir,'/profile'],Cmd),
    time(shell(Cmd)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Pretty printer
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
result_descriptors([
			  res(section,3,'.facts'),
			  res(instruction,6,'.facts'),
			  res(op_regdirect,2,'.facts'),
			  res(op_immediate,2,'.facts'),
			  res(op_indirect,7,'.facts'),

			  res(direct_jump,2,'.csv'),	
			  res(reg_jump,1,'.csv'),
			  res(indirect_jump,1,'.csv'),
			  res(pc_relative_jump,2,'.csv'),

			  res(direct_call,2,'.csv'),

			  %res(possible_target,'phase2-possible_target',1,'.csv'),
			  res(likely_ea,'likely_ea_final',2,'.csv'),
			  res(remaining_ea,'phase2-remaining_ea',1,'.csv'),
			  res(function_symbol,2,'.csv'),
			  res(chunk_start,1,'.csv'),
			  res(chunk_overlap,'chunk_overlap2',2,'.csv'),
			  res(discarded_chunk,1,'.csv'),

			  res(symbolic_imm,2,'.csv'),
			  res(op_points_to_data,1,'.csv')

		      ]).

:-dynamic section/3.
:-dynamic instruction/6.
:-dynamic op_regdirect/2.
:-dynamic op_immediate/2.
:-dynamic op_indirect/7.

:-dynamic direct_jump/2.
:-dynamic reg_jump/1.
:-dynamic indirect_jump/1.
:-dynamic pc_relative_jump/2.

:-dynamic direct_call/2.

:-dynamic likely_ea/2.
:-dynamic remaining_ea/1.
:-dynamic function_symbol/2.

:-dynamic chunk_start/1.
:-dynamic chunk_overlap/2.
:-dynamic discarded_chunk/1.

:-dynamic symbolic_imm/2.
:-dynamic op_points_to_data/1.

collect_results(Dir,results(Results)):-
    result_descriptors(Descriptors),
    maplist(collect_result(Dir),Descriptors,Results).

collect_result(Dir,res(Name,Filename,Arity,Ending),Result):-
    atom_concat(Filename,Ending,Name_file),
    directory_file_path(Dir,Name_file,Path),
    csv_read_file(Path, Result, [functor(Name), arity(Arity),separator(0'\t)]),
    maplist(assertz,Result).

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
    get_chunks(Chunks),
    maplist(pp_chunk, Chunks).


get_chunks(Chunks):-
    findall(Chunk,chunk_start(Chunk),Chunk_addresses),
    findall(Instruction,
	    (instruction(EA,Size,Name,Opc1,Opc2,Opc3),
	    \+likely_ea(EA,_),
	    remaining_ea(EA),
	    get_op(Opc1,Op1),
	    get_op(Opc2,Op2),
	    get_op(Opc3,Op3),
	    Instruction=instruction(EA,Size,Name,Op1,Op2,Op3)
	    ),Single_instructions),
     empty_assoc(Empty),
     foldl(get_chunk_content,Chunk_addresses,Empty,Map),
     foldl(accum_instruction,Single_instructions,Map,Map2),
     assoc_to_list(Map2,Chunks).

get_chunk_content(Chunk_addr,Assoc,Assoc1):-
    findall(Instruction,
	    (likely_ea(EA,Chunk_addr),
	     instruction(EA,Size,Name,Opc1,Opc2,Opc3),	     
	     get_op(Opc1,Op1),
	     get_op(Opc2,Op2),
	     get_op(Opc3,Op3),
	     Instruction=instruction(EA,Size,Name,Op1,Op2,Op3)
	    ),Instructions),
    put_assoc(Chunk_addr,Assoc,chunk(Instructions),Assoc1).


accum_instruction(instruction(EA,Size,OpCode,Op1,Op2,Op3),Assoc,Assoc1):-
    put_assoc(EA,Assoc,instruction(EA,Size,OpCode,Op1,Op2,Op3),Assoc1).


pp_chunk(EA_chunk-chunk(List)):-
    !,
    get_chunk_comments(EA_chunk,Comments),
    ((discarded_chunk(EA_chunk),\+option('-debug'))->
	 true
     ;
     print_section_header(EA_chunk),
    
     (is_function(EA_chunk,Name)->
	 print_function_header(Name)
      ;
      format('~n  Label ~16R:',[EA_chunk]) 
     ),!,
     print_comments(Comments),nl,
     maplist(pp_instruction,List),nl
    ).

pp_chunk(_EA_chunk-Instruction):-
    (option('-debug')->
	 pp_instruction(Instruction)
     ;	 
     true
    ).

print_section_header(EA):-
    section(Section_name,_,EA),!,
    format('~n~n;=================================== ~n',[]),
    format(';  Section ~p:~n',[Section_name]),
    format(';=================================== ~n~n',[]).
print_section_header(_).

is_function(EA,Name):-
    function_symbol(EA,Name).
is_function(EA,'unkown'):-
      direct_call(_,EA).

print_function_header(Name):-
    	 format(';----------------------------------- ~n',[]),
	 format(';  Function ~p:~n',[Name]),
	 format(';----------------------------------- ~n',[]).
		
get_chunk_comments(EA_chunk,Comments):-
	setof(Comment,chunk_comment(EA_chunk,Comment),Comments),!.
get_chunk_comments(_EA_chunk,[]).
    
chunk_comment(EA,discarded):-
    discarded_chunk(EA).

chunk_comment(EA,overlap_with(Str_EA2)):-
    chunk_overlap(EA2,EA),
    format(string(Str_EA2),'~16R',[EA2]).

chunk_comment(EA,overlap_with(Str_EA2)):-
    chunk_overlap(EA,EA2),
    format(string(Str_EA2),'~16R',[EA2]).

chunk_comment(EA,is_called):-
    direct_call(_,EA).

chunk_comment(EA,jumped_from(Str_or)):-
    direct_jump(Or,EA),
    format(string(Str_or),'~16R',[Or]).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


pp_instruction(instruction(EA,_Size,OpCode,Op1,Op2,Op3)):-
    exclude(\Op^(Op=none),[Op1,Op2,Op3],Ops),
    maplist(pp_op,Ops,Pretty_ops),
    %useful info
    convlist(get_comment,Ops,Op_comments),
    get_ea_comments(EA,Comments),
    append(Comments,Op_comments,All_comments),
    reverse(Pretty_ops,Pretty_ops_rev),	
    format('         ~16R:   ~p',[EA,OpCode]), 
    maplist(print_with_space,Pretty_ops_rev),
    % print the names of the immediates if they are functions
    print_comments(All_comments),
    nl.

pp_instruction(_).


print_comments(Comments):-
    (Comments\=[]->
	 format('          # ',[]),
	 maplist(print_with_space,Comments)
     ;true
    ).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

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
 

%%%%%%%%%%%%%%%%%%%
% comments on instructions based on ea

get_ea_comments(EA,Comments):-
    setof(Comment,
	  ea_comment(EA,Comment),
	  Comments),!.
get_ea_comments(_EA,[]).

ea_comment(EA,not_in_chunk):-
\+likely_ea(EA,_).

ea_comment(EA,symbolic_ops(Symbolic_ops)):-
    findall(Op_num,symbolic_imm(EA,Op_num),Symbolic_ops),
    Symbolic_ops\=[].


ea_comment(EA,reg_jump):-
    reg_jump(EA).
ea_comment(EA,indirect_jump):-
    indirect_jump(EA).

ea_comment(EA,pc_relative_jump(Dest)):-
    pc_relative_jump(EA,Dest).



%%%%%%%%%%%%%%%%%%%
% comments on instructions based on the operators

get_comment(Op,Name):-
    Op=immediate(Num),
    Num\=0,
    function_symbol(Num,Name).

	 
%%%%%%%%%%%%%%%%%%%%


print_stats:-
    format('~n~nResult statistics:~n',[]),
    result_descriptors(Descriptors),
    maplist(print_descriptor_stats,Descriptors).

print_descriptor_stats(Res):-
    (Res=res(Name,Arity,_)
     ;
     Res=res(Name,_,Arity,_)
    ),
    functor(Head,Name,Arity),
    findall(Head,Head,Results),
    length(Results,N),
    format(' Number of ~p: ~p~n',[Name,N]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
generate_hints(Dir):-
    option('-hints'),!,
    findall(Code_ea,
	    (
		likely_ea(Code_ea,Chunk),
		chunk_start(Chunk),
		\+discarded_chunk(Chunk)

	    ),Code_eas),
    directory_file_path(Dir,'hints',Path),
    open(Path,write,S),
    maplist(print_code_ea(S),Code_eas),
    close(S).

generate_hints(_).    

print_code_ea(S,EA):-
    format(S,'0x~16R C',[EA]),
    instruction(EA,_,_,Op1,Op2,Op3),
    exclude(\OP^(OP=0),[Op1,Op2,Op3],Non_zero_ops),
    length(Non_zero_ops,N_ops),
    findall(Index,symbolic_imm(EA,Index),Indexes),
    transform_indexes(Indexes,N_ops,Indexes_tr),
    maplist(print_sym_index(S),Indexes_tr),
    format(S,'~n',[]).

transform_indexes(Indexes,N_ops,Indexes_tr):-
    foldl(transform_index(N_ops),Indexes,[],Indexes_tr).

transform_index(N_ops,Index,Accum,[Index_tr|Accum]):-
    Index_tr is N_ops-Index.
 
print_sym_index(S,I):-
      	 format(S,'so~p@0',[I]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% auxiliary predicates
hex_to_dec(Hex,Dec):-
    hex_bytes(Hex,Bytes),
    byte_list_to_num(Bytes,0,Dec).

byte_list_to_num([],Accum,Accum).
byte_list_to_num([Byte|Bytes],Accum,Dec):-
    Accum2 is Byte+256*Accum,
    byte_list_to_num(Bytes,Accum2,Dec).


print_with_space(Op):-
    format(' ~p ',[Op]).
