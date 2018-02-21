:-module(disasm_driver,[disasm_binary/1]).


valid_option('-hints').
valid_option('-debug').
valid_option('-debug_all').
valid_option('-asm').

sections([
		%	'.eh_frame',
		'.text',
		'.plt',
		'.init',
		'.fini']).
data_sections([
		     '.got',
		     '.plt.got',
		      '.got.plt',
		     '.data',
		     '.rodata']).

% the things that are ignored with the parameter -asm
:-dynamic asm_skip_function/1.
asm_skip_function('_start').
asm_skip_function('deregister_tm_clones').
asm_skip_function('register_tm_clones').
asm_skip_function('__do_global_dtors_aux').
asm_skip_function('frame_dummy').
asm_skip_function('__libc_csu_fini').
asm_skip_function('__libc_csu_init').

asm_skip_section('.comment').
asm_skip_section('.plt').
asm_skip_section('.init').
asm_skip_section('.fini').
asm_skip_section('.got').
asm_skip_section('.plt.got').
asm_skip_section('.got.plt').


disasm_binary([File|Args]):-
    maplist(save_option,Args),
    set_prolog_flag(print_write_options,[quoted(false)]),

    (option('-asm')->format('/*~n',[]);true),
    
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

     (option('-asm')->format('*/~n',[]);true),
     pretty_print_results,
     print_stats
    ).

:-dynamic option/1.


save_option(Arg):-
    valid_option(Arg),
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
    format('#cmd: ~p~n',[Cmd]),
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
			  result(symbol,5,'.facts'),
			  result(section,3,'.facts'),
			  result(instruction,6,'.facts'),
			  result(op_regdirect,2,'.facts'),
			  result(op_immediate,2,'.facts'),
			  result(op_indirect,8,'.facts'),
			  result(data_byte,2,'.facts'),

			  result(direct_jump,2,'.csv'),	
			  result(reg_jump,1,'.csv'),
			  result(indirect_jump,1,'.csv'),
			  result(pc_relative_jump,2,'.csv'),
			  
			  result(direct_call,2,'.csv'),
			  result(reg_call,1,'.csv'),
			  result(indirect_call,1,'.csv'),
			  result(pc_relative_call,2,'.csv'),

			  result(plt_reference,2,'.csv'),

			  %result(possible_target,'phase2-possible_target',1,'.csv'),
			  named_result(likely_ea,'likely_ea_final',2,'.csv'),
			  named_result(remaining_ea,'phase2-remaining_ea',1,'.csv'),
			  named_result(chunk_overlap,'chunk_overlap2',2,'.csv'),

			  result(function_symbol,2,'.csv'),
			 % result(ambiguous_function_symbol,1,'.csv'),
			  result(chunk_start,1,'.csv'),
			  result(discarded_chunk,1,'.csv'),

			  result(symbolic_operand,2,'.csv'),
			  result(labeled_data,1,'.csv'),
			  result(float_data,1,'.csv'),
			  result(pointer,2,'.csv'),
			  result(string,2,'.csv'),

			  result(bss_data,1,'.csv')
		      ]).

:-dynamic symbol/5.
:-dynamic section/3.
:-dynamic instruction/6.
:-dynamic op_regdirect/2.
:-dynamic op_immediate/2.
:-dynamic op_indirect/8.
:-dynamic data_byte/2.


:-dynamic direct_jump/2.
:-dynamic reg_jump/1.
:-dynamic indirect_jump/1.
:-dynamic pc_relative_jump/2.


:-dynamic direct_call/2.
:-dynamic reg_call/1.
:-dynamic indirect_call/1.
:-dynamic pc_relative_call/2.
:-dynamic plt_reference/2.

:-dynamic likely_ea/2.
:-dynamic remaining_ea/1.
:-dynamic function_symbol/2.
%:-dynamic ambiguous_function_symbol/2.

:-dynamic chunk_start/1.
:-dynamic chunk_overlap/2.
:-dynamic discarded_chunk/1.

:-dynamic symbolic_operand/2.
:-dynamic labeled_data/1.
:-dynamic float_data/1.
:-dynamic pointer/2.
:-dynamic string/2.

:-dynamic bss_data/1.

collect_results(Dir,results(Results)):-
    result_descriptors(Descriptors),
    maplist(collect_result(Dir),Descriptors,Results).

collect_result(Dir,named_result(Name,Filename,Arity,Ending),Result):-
    atom_concat(Filename,Ending,Name_file),
    directory_file_path(Dir,Name_file,Path),
    csv_read_file(Path, Result, [functor(Name), arity(Arity),separator(0'\t)]),
    maplist(assertz,Result).

collect_result(Dir,result(Name,Arity,Ending),Result):-
    atom_concat(Name,Ending,Name_file),
    directory_file_path(Dir,Name_file,Path),
    csv_read_file(Path, Result, [functor(Name), arity(Arity),separator(0'\t)]),
    maplist(assertz,Result).



print_stats:-
    format('~n~n#Result statistics:~n',[]),
    result_descriptors(Descriptors),
    maplist(print_descriptor_stats,Descriptors).

print_descriptor_stats(Res):-
    (Res=result(Name,Arity,_)
     ;
     Res=named_result(Name,_,Arity,_)
    ),
    functor(Head,Name,Arity),
    findall(Head,Head,Results),
    length(Results,N),
    format(' # Number of ~p: ~p~n',[Name,N]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

pretty_print_results:-
    print_header,
    get_chunks(Chunks),
    maplist(pp_chunk, Chunks),
    get_data(Data),
    maplist(pp_data,Data),
    get_bss_data(Uninitialized_data),
    format('.bss~n',[]),
    maplist(pp_bss_data,Uninitialized_data).



print_header:-
    option('-asm'),!,
    format('
.intel_syntax noprefix
.globl	main
.type	main, @function
.text ~n',[]).
print_header.



get_chunks(Chunks):-
    findall(Chunk,
	    (
	     chunk_start(Chunk),
	     \+discarded_chunk(Chunk)
	    ),Chunk_addresses),
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


get_op(0,none):-!.
get_op(N,reg(Name)):-
    op_regdirect(N,Name),!.
get_op(N,immediate(Immediate)):-
    op_immediate(N,Immediate),!.
get_op(N,indirect(Reg1,Reg2,Reg3,A,B,C,Size)):-
    op_indirect(N,Reg1,Reg2,Reg3,A,B,C,Size),!.


get_data(Data_groups):-
    findall(Data_byte,
	    (data_byte(EA,Content),
	     Data_byte=data_byte(EA,Content)
	    ),Data),
    group_data(Data,Data_groups).

group_data([],[]).

group_data([data_byte(EA,_)|Rest],[data_group(EA,plt_ref,Function)|Groups]):-
    pointer(EA,_Group_content),
    plt_reference(EA,Function),!,
    split_at(7,Rest,_,Rest2),
    group_data(Rest2,Groups).

group_data([data_byte(EA,_)|Rest],[data_group(EA,labeled_pointer,Group_content)|Groups]):-
    pointer(EA,Group_content),
    labeled_data(EA),!,
    split_at(7,Rest,_,Rest2),
    group_data(Rest2,Groups).

group_data([data_byte(EA,_)|Rest],[data_group(EA,pointer,Group_content)|Groups]):-
    pointer(EA,Group_content),!,
    split_at(7,Rest,_,Rest2),
    group_data(Rest2,Groups).

group_data([data_byte(EA,Content)|Rest],[data_group(EA,float,Group_content)|Groups]):-
    float_data(EA),!,
    split_at(4,[data_byte(EA,Content)|Rest],Group_content,Rest2),
    group_data(Rest2,Groups).

group_data([data_byte(EA,Content)|Rest],[data_group(EA,string,String)|Groups]):-
    string(EA,End),!,
    Size is End-EA,
    split_at(Size,[data_byte(EA,Content)|Rest],Data_bytes,Rest2),
    append(String_bytes,[_],Data_bytes),
    maplist(get_data_byte_content,String_bytes,Bytes),
    clean_special_characters(Bytes,Bytes_clean),
    string_codes(String,Bytes_clean),
    group_data(Rest2,Groups).

group_data([data_byte(EA,Content)|Rest],[data_group(EA,unknown,[data_byte(EA,Content)])|Groups]):-
    labeled_data(EA),!,
    group_data(Rest,Groups).

group_data([data_byte(EA,Content)|Rest],[data_byte(EA,Content)|Groups]):-
    group_data(Rest,Groups).

clean_special_characters([],[]).
%double quote
clean_special_characters([34|Codes],[92,34|Clean_codes]):-
    !,
    clean_special_characters(Codes,Clean_codes).
% the single quote
clean_special_characters([39|Codes],[92,39|Clean_codes]):-
    !,
    clean_special_characters(Codes,Clean_codes).
%newline
clean_special_characters([10|Codes],[92,110|Clean_codes]):-
    !,
    clean_special_characters(Codes,Clean_codes).
%scape character
clean_special_characters([92|Codes],[92,92|Clean_codes]):-
    !,
    clean_special_characters(Codes,Clean_codes).

clean_special_characters([Code|Codes],[Code|Clean_codes]):-
    clean_special_characters(Codes,Clean_codes).

split_at(N,List,FirstN,Rest):-
    length(FirstN,N),
    append(FirstN,Rest,List).

get_data_byte_content(data_byte(_,Content),Content).


get_bss_data(Data_elements):-
    section('.bss',SizeSect,Base),
    End is Base+SizeSect,
      setof(EA,
	    EA^(
		bss_data(EA)
	     ;
	     %the last border
	     EA=End
	    )
	    ,Addresses),
      group_bss_data(Addresses,Data_elements).

group_bss_data([],[]).
group_bss_data([_Last],[]).
group_bss_data([Start,Next|Rest],[variable(Start,Size)|Rest_vars]):-
		   Size is Next-Start,
		   group_bss_data([Next|Rest],Rest_vars).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

skip_data_ea(EA):-
    option('-asm'),
    asm_skip_section(Section),
    is_in_section(EA,Section).
skip_ea(EA):-
    option('-asm'),
    ( asm_skip_section(Section),
      is_in_section(EA,Section)
     ;
     asm_skip_function(Function),
     is_in_function(EA,Function)
    ).
     
is_in_section(EA,Name):-
    section(Name,Size,Base),
    EA>=Base,
    End is Base+Size,
    EA<End.
is_in_function(EA,Name):-
    function_symbol(EA_fun,Name),
    % there is no function in between
    EA>=EA_fun,
    \+ (
	function_symbol(EA_fun2,_),
	EA_fun2=<EA,
	EA_fun2>EA_fun
       ).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

pp_data(data_group(EA,_,_)):-
    skip_data_ea(EA),!.
pp_data(data_byte(EA,_)):-
    skip_data_ea(EA),!.

pp_data(data_group(EA,plt_ref,Function)):-
    print_section_header(EA),
    print_label(EA),
    print_ea(EA),
    format('.quad ~s~n',[Function]).

pp_data(data_group(EA,pointer,Content)):-
    print_section_header(EA),
    print_ea(EA),
    format('.quad L_~16R~n',[Content]).
     
pp_data(data_group(EA,labeled_pointer,Content)):-
    print_section_header(EA),
    print_label(EA),
    print_ea(EA),
    format('.quad L_~16R~n',[Content]).
   
pp_data(data_group(EA,float,Content)):-
    print_section_header(EA),
    print_label(EA),
    format('# float~n',[]),
    maplist(pp_data,Content).

pp_data(data_group(EA,string,Content)):-
    print_section_header(EA),
    print_label(EA),
    print_ea(EA),
    set_prolog_flag(character_escapes, false),
    format('.string "~p"~n',[Content]),
    set_prolog_flag(character_escapes, true).

pp_data(data_group(EA,unknown,Content)):-
    print_section_header(EA),
    print_label(EA),
    maplist(pp_data,Content).

pp_data(data_byte(EA,Content)):-
    print_section_header(EA),
    print_ea(EA),
    format('.byte 0x~16R~n',[Content]).

print_ea(_):-
    option('-asm'),!,
    format('          ',[]).

print_ea(EA):-
    format('         ~16R: ',[EA]).

print_label(EA):-
    (get_global_symbol_name(EA,Name)->
	 format('~p:~n',[Name])
     ;
     true
    ),
     format('L_~16R:~n',[EA]).





%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% pp_bss_data(variable(Start,Size)):-
%%     get_global_symbol_name(Start,Name),!,
%%     format('~p:~n',[Name]),
%%     format('.comm L_~16R, ~p ~n',[Start,Size]).

pp_bss_data(variable(Start,Size)):-
    format('L_~16R: .zero  ~p ~n',[Start,Size]).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

pp_chunk(EA_chunk-chunk(_List)):-
    skip_ea(EA_chunk),!.

pp_chunk(EA_chunk-chunk(List)):-
    !,
    print_section_header(EA_chunk),
    print_function_header(EA_chunk),
    print_label(EA_chunk),   
    (option('-debug')->
	 get_comments(EA_chunk,Comments),
	 print_comments(Comments),nl
     ;
     true),
    maplist(pp_instruction,List),nl.

pp_chunk(EA_chunk-Instruction):-
    print_section_header(EA_chunk),
    (option('-debug_all')->
	 pp_instruction(Instruction)
     ;	 
     true
    ).

print_section_header(EA):-
    section('.text',_,EA),!,
    format('~n~n#=================================== ~n',[]),
    format('.text~n',[]),
    format('#=================================== ~n~n',[]).

print_section_header(EA):-
    section(Section_name,_,EA),!,
    format('~n~n#=================================== ~n',[]),
    format('.section ~p~n',[Section_name]),
    format('#=================================== ~n~n',[]).
print_section_header(_).



print_function_header(EA):-
    is_function(EA,Name),
    format('#----------------------------------- ~n',[]),
    format('.globl ~p~n',[Name]),
    format('.type ~p, @function~n',[Name]),
    format('~p:~n',[Name]),
    format('#----------------------------------- ~n',[]).

print_function_header(_).

is_function(EA,'main'):-
    function_symbol(EA,'main').
is_function(EA,Name_complete):-
    function_symbol(EA,Name),
    %symbol names do not have to be unique!
    format(string(Name_complete),'~p_~16R',[Name,EA]).
is_function(EA,Funtion_name):-
    direct_call(_,EA),
    atom_concat('unknown_function_',EA,Funtion_name).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% these opcodes do not really exist
adapt_opcode(fmul_to,fmul).
adapt_opcode(fsubr_to,fsub).
adapt_opcode(movsd2,movsd).
adapt_opcode(imul2,imul).
adapt_opcode(imul3,imul).
adapt_opcode(imul1,imul).
adapt_opcode(cmpsd3,cmpsd).
adapt_opcode(Operation,Operation).

opcode_suffix(Opcode,Suffix):-
    atom_codes(Opcode,Codes),
    atom_codes(' ',[Space]),
    append(_Prefix,[Space|Suffix_codes],Codes),!,
    atom_codes(Suffix,Suffix_codes).
opcode_suffix(Opcode,Opcode).


pp_instruction(instruction(EA,_Size,String_op,Op1,none,none)):-
    opcode_suffix(String_op,Op_suffix),
    member(Op_suffix,['MOVS','CMPS']),!,
    print_ea(EA),
    downcase_atom(String_op,OpCode_l),
    get_op_indirect_size_suffix(Op1,Suffix),
    format(' ~p~p',[OpCode_l,Suffix]),
    (option('-debug')->
	 get_comments(EA,Comments),
	 print_comments(Comments)
     ;
     true
    ),
    nl.
pp_instruction(instruction(EA,_Size,OpCode,Op1,Op2,Op3)):-
    print_ea(EA),
    downcase_atom(OpCode,OpCode_l),
    adapt_opcode(OpCode_l,OpCode_adapted),
    format(' ~p',[OpCode_adapted]),
    %operands
    pp_operand_list([Op1,Op2,Op3],EA,1,Pretty_ops),
    % print the operands in the order: dest, src1 src2
    (append(Source_operands,[Dest_operand],Pretty_ops),
     print_with_sep([Dest_operand|Source_operands],',')
     ;
     %unless there are no operands
     Pretty_ops=[]
    ),
    (option('-debug')->
	 get_comments(EA,Comments),
	 print_comments(Comments)
     ;
     true
    ),
    nl.


is_none(none).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
pp_operand_list([],_EA,_N,[]).
pp_operand_list([none|Ops],EA,N,Pretty_ops):-
    pp_operand_list(Ops,EA,N,Pretty_ops).
pp_operand_list([Op|Ops],EA,N,[Op_pretty|Pretty_ops]):-
    pp_operand(Op,EA,N,Op_pretty),
    N1 is N+1,
    pp_operand_list(Ops,EA,N1,Pretty_ops).

pp_operand(reg(Name),_,_,Name2):-
    adapt_register(Name,Name2).

pp_operand(immediate(_Num),EA,1,Name):-
    plt_reference(EA,Name),!.



pp_operand(immediate(_Num),EA,_N,Name_complete):-
    direct_call(EA,Dest),
    function_symbol(Dest,Name),!,
    %symbol names do not have to be unique!
    format(string(Name_complete),'~p_~16R',[Name,Dest]).

% special case for mov from symbolic
pp_operand(immediate(Num),EA,1,Num_hex):-
    symbolic_operand(EA,1),!,
  %  instruction(EA,_,'MOV',_,_,_),!,
    format(string(Num_hex),'OFFSET L_~16R',[Num]).

pp_operand(immediate(Num),EA,N,Num_hex):-
    symbolic_operand(EA,N),!,
    format(string(Num_hex),'L_~16R',[Num]).



pp_operand(immediate(Num),_,_,Num).
    

pp_operand(indirect('NullSReg','NullReg64','NullReg64',1,0,_,Size),_,_,PP):-
      get_size_name(Size,Name),
      format(atom(PP),'~p [~p]',[Name,0]).

pp_operand(indirect('NullSReg',Reg,'NullReg64',1,0,_,Size),_,_,PP):-
      adapt_register(Reg,Reg_adapted),
      get_size_name(Size,Name),
      format(atom(PP),'~p [~p]',[Name,Reg_adapted]).

% special case for rip relative addressing
pp_operand(indirect('NullSReg','RIP','NullReg64',1,Offset,_,Size),EA,N,PP):-
    symbolic_operand(EA,N),!,
    get_size_name(Size,Name),
    instruction(EA,Size_instr,_,_,_,_),
    Address is EA+Offset+Size_instr,
    (get_global_symbol_name(Address,Name_symbol)->
	 format(atom(PP),'~p [~p]',[Name,Name_symbol])
     ;
	 format(atom(PP),'~p [L_~16R]',[Name,Address])
    ).

pp_operand(indirect('NullSReg','NullReg64','NullReg64',1,Offset,_,Size),EA,N,PP):-
    get_offset_and_sign(Offset,EA,N,Offset1,PosNeg),
    get_size_name(Size,Name),
    Term=..[PosNeg,Offset1],
    format(atom(PP),'~p ~p',[Name,[Term]]).

pp_operand(indirect('NullSReg',Reg,'NullReg64',1,Offset,_,Size),EA,N,PP):-
    adapt_register(Reg,Reg_adapted),
    get_offset_and_sign(Offset,EA,N,Offset1,PosNeg),
    get_size_name(Size,Name),
    Term=..[PosNeg,Reg_adapted,Offset1],
    format(atom(PP),'~p ~p',[Name,[Term]]).

pp_operand(indirect('NullSReg','NullReg64',Reg_index,Mult,Offset,_,Size),EA,N,PP):-
    adapt_register(Reg_index,Reg_index_adapted),
    get_offset_and_sign(Offset,EA,N,Offset1,PosNeg),
    get_size_name(Size,Name),
    Term=..[PosNeg,Reg_index_adapted*Mult,Offset1],
    format(atom(PP),'~p ~p',[Name,[Term]]).


pp_operand(indirect('NullSReg',Reg,Reg_index,Mult,0,_,Size),_,_N,PP):-
    adapt_register(Reg,Reg_adapted),
    adapt_register(Reg_index,Reg_index_adapted),
    get_size_name(Size,Name),
    format(atom(PP),'~p ~p',[Name,[Reg_adapted+Reg_index_adapted*Mult]]).


pp_operand(indirect('NullSReg',Reg,Reg_index,Mult,Offset,_,Size),EA,N,PP):-
    adapt_register(Reg,Reg_adapted),
    adapt_register(Reg_index,Reg_index_adapted),
    get_size_name(Size,Name),
    get_offset_and_sign(Offset,EA,N,Offset1,PosNeg),
    Term=..[PosNeg,Reg_adapted+Reg_index_adapted*Mult,Offset1],
    format(atom(PP),'~p ~p',[Name,[Term]]).


pp_operand(indirect(SReg,'NullReg64','NullReg64',1,Offset,_,Size),EA,N,PP):-
    get_size_name(Size,Name),
    get_offset_and_sign(Offset,EA,N,Offset1,PosNeg),
    Term=..[PosNeg,Offset1],
    format(atom(PP),'~p ~p',[Name,[SReg:Term]]).



get_offset_and_sign(Offset,EA,N,Offset1,'+'):-
    symbolic_operand(EA,N),!,
    format(atom(Offset1),'L_~16R',[Offset]).
get_offset_and_sign(Offset,_EA,_N,Offset1,'-'):-
    Offset<0,!,
    Offset1 is 0-Offset.
get_offset_and_sign(Offset,_EA,_N,Offset,'+').



    
get_size_name(128,'').
get_size_name(0,'').
get_size_name(64,'QWORD PTR').
get_size_name(32,'DWORD PTR').
get_size_name(16,'WORD PTR').
get_size_name(8,'BYTE PTR').
get_size_name(Other,size(Other)).

get_op_indirect_size_suffix(indirect(_,_,_,_,_,_,Size),Suffix):-
    get_size_suffix(Size,Suffix).

get_size_suffix(128,'').
get_size_suffix(0,'').
get_size_suffix(64,'q').
get_size_suffix(32,'d').
get_size_suffix(16,'w').
get_size_suffix(8,'b').


adapt_register('R8L','R8B'):-!.
adapt_register('R9L','R9B'):-!.
adapt_register('R10L','R10B'):-!.
adapt_register('R11L','R11B'):-!.
adapt_register('R12L','R12B'):-!.
adapt_register('R13L','R13B'):-!.
adapt_register('R14L','R14B'):-!.
adapt_register('R15L','R15B'):-!.

adapt_register('ST0','ST(0)'):-!.
adapt_register('ST1','ST(1)'):-!.
adapt_register('ST2','ST(2)'):-!.
adapt_register('ST3','ST(3)'):-!.
adapt_register('ST4','ST(4)'):-!.
adapt_register('ST5','ST(5)'):-!.
adapt_register('ST6','ST(6)'):-!.
adapt_register('ST7','ST(7)'):-!.
adapt_register(Reg,Reg).

%%%%%%%%%%%%%%%%%%%
% comments for debugging

    

get_comments(EA_chunk,Comments):-
	setof(Comment,comment(EA_chunk,Comment),Comments),!.
get_comments(_EA_chunk,[]).
    
comment(EA,discarded):-
    discarded_chunk(EA).

comment(EA,overlap_with(Str_EA2)):-
    chunk_overlap(EA2,EA),
    format(string(Str_EA2),'~16R',[EA2]).

comment(EA,overlap_with(Str_EA2)):-
    chunk_overlap(EA,EA2),
    format(string(Str_EA2),'~16R',[EA2]).

comment(EA,is_called):-
    direct_call(_,EA).

comment(EA,jumped_from(Str_or)):-
    direct_jump(Or,EA),
    format(string(Str_or),'~16R',[Or]).

comment(EA,not_in_chunk):-
    \+likely_ea(EA,_).

comment(EA,symbolic_ops(Symbolic_ops)):-
    findall(Op_num,symbolic_operand(EA,Op_num),Symbolic_ops),
    Symbolic_ops\=[].

comment(EA,reg_jump):-
    reg_jump(EA).
comment(EA,indirect_jump):-
    indirect_jump(EA).

comment(EA,plt(Dest)):-
    plt_reference(EA,Dest).


comment(EA,pc_relative_jump(Dest_hex)):-
    pc_relative_jump(EA,Dest),
    format(atom(Dest_hex),'~16R',[Dest]).

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
    findall(Data_ea,
	    (
		labeled_data(Data_ea)
	     ;
	     pointer(Data_ea,_)
	    )
	    ,Data_eas),
    maplist(print_data_ea(S),Data_eas),
    close(S).

generate_hints(_).    

print_code_ea(S,EA):-
    format(S,'0x~16R C',[EA]),
    instruction(EA,_,_,Op1,Op2,Op3),
    exclude(is_zero,[Op1,Op2,Op3],Non_zero_ops),
    length(Non_zero_ops,N_ops),
    findall(Index,symbolic_operand(EA,Index),Indexes),
    transform_indexes(Indexes,N_ops,Indexes_tr),
    maplist(print_sym_index(S),Indexes_tr),
    format(S,'~n',[]).

is_zero(0).
print_data_ea(S,EA):-
    format(S,'0x~16R D~n',[EA]).

transform_indexes(Indexes,N_ops,Indexes_tr):-
    foldl(transform_index(N_ops),Indexes,[],Indexes_tr).

transform_index(N_ops,Index,Accum,[Index_tr|Accum]):-
    Index_tr is N_ops-Index.
 
print_sym_index(S,I):-
      	 format(S,'so~p@0',[I]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% auxiliary predicates

print_comments(Comments):-
    (Comments\=[]->
	 format('          # ',[]),
	 maplist(print_with_space,Comments)
     ;true
    ).

hex_to_dec(Hex,Dec):-
    hex_bytes(Hex,Bytes),
    byte_list_to_num(Bytes,0,Dec).

byte_list_to_num([],Accum,Accum).
byte_list_to_num([Byte|Bytes],Accum,Dec):-
    Accum2 is Byte+256*Accum,
    byte_list_to_num(Bytes,Accum2,Dec).


print_with_space(Op):-
    format(' ~p ',[Op]).

print_with_sep([],_).
print_with_sep([Last],_):-
    !,
    format(' ~p ',[Last]).
print_with_sep([X|Xs],Sep):-
    format(' ~p~p ',[X,Sep]),
    print_with_sep(Xs,Sep).


get_global_symbol_name(Address,Name):-
    symbol(Address,_,_,'GLOBAL',Name_symbol),
    clean_symbol_name_suffix(Name_symbol,Name).

clean_symbol_name_suffix(Name,Name_clean):-
    atom_codes(Name,Codes),
    atom_codes('@',[At]),
    append(Name_clean_codes,[At,At|_Suffix],Codes),!,
    atom_codes(Name_clean,Name_clean_codes).

%clean_symbol_name_suffix(Name,Name).
