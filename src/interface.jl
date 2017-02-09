using DebuggerFramework

function get_insts(session, modules, ip)
    base, mod = NativeDebugger.find_module(session, modules, UInt(ip))
    modrel = UInt(UInt(ip)-base)
    if isa(mod, NativeDebugger.SyntheticModule)
        bounds = mod.get_proc_bounds(session, ip)
        insts = NativeDebugger.load(session, NativeDebugger.RemotePtr{UInt8}(base+first(bounds)),
          length(bounds))
        return base, first(bounds), insts
    end
    if isnull(mod.xpdata)
        loc, fde = NativeDebugger.Unwinder.find_fde(mod, modrel)
        seekloc = loc
        cie = CallFrameInfo.realize_cie(fde)
        nbytes = UInt(CallFrameInfo.fde_range(fde, cie))
    else
        entry = NativeDebugger.Unwinder.find_seh_entry(mod, modrel)
        loc = entry.start
        # Need to translate from virtual to file addresses. Hardcode 0xa00 for
        # now.
        seekloc = loc - 0xa00
        nbytes = entry.stop - entry.start
    end
    if ObjFileBase.isrelocatable(handle(mod))
        # For JIT frames, base is the start of .text, so we need to add that
        # offset back
        text = first(filter(x->sectionname(x)==
            ObjFileBase.mangle_sname(handle(mod),"text"),Sections(handle(mod))))
        seekloc += sectionoffset(text)
    elseif isa(handle(mod), ELF.ELFHandle)
        # In weird executables, the executable segment may not be at offset 0
        phs = ELF.ProgramHeaders(handle(mod))
        idx = findfirst(p->p.p_type==ELF.PT_LOAD &&
                           ((p.p_flags & ELF.PF_X) != 0), phs)
        seekloc += phs[idx].p_offset
    elseif isa(handle(mod), COFF.COFFHandle)
        text = ObjFileBase.deref(first(filter(x->sectionname(x)==
            ObjFileBase.mangle_sname(handle(mod),"text"),Sections(handle(mod)))))
        seekloc -= text.VirtualAddress
        seekloc += text.PointerToRawData
    end
    seek(handle(mod), seekloc)
    insts = read(handle(mod), UInt8, nbytes)
    base, loc, insts
end

function triple_for_sess(sess)
    if isa(NativeDebugger.getarch(sess), NativeDebugger.X86_64.X86_64Arch)
        return "x86_64-linux-gnu"
    else
        return "i386-linux-gnu"
    end
end

demangle(name) = name
function symbolicate_frame(frame::PhysicalStackFrame)
    found = false
    symb = "Unkown"
    try
        found, symb = NativeDebugger.Unwinder.symbolicate(frame.session,
          frame.modules,
          UInt64(NativeDebugger.ip(frame.RC)))
        symb = demangle(symb)
        !found && (symb = "Most likely $symb")
    catch err
        (!isa(err, ErrorException) || !contains(err.msg, "found")) && rethrow(err)
    end
    found, symb
end

function DebuggerFramework.locdesc(frame::PhysicalStackFrame)
    symbolicate_frame(frame)[2]
end

function DebuggerFramework.print_status_synthtic(io::IO, state, frame::PhysicalStackFrame, lines_before, total_lines)
    ipoffset = 0
    ipbase = NativeDebugger.ip(frame)
    try
        # Try disassembling at the start of the function, highlighting the
        # current ip.
        base, loc, insts = get_insts(frame.session, frame.modules, ipbase)
        ipbase = base+loc
        ipoffset = UInt64(ipbase-loc-base-(isstacktop(frame)?0:1))
        disasm_around_ip(io, insts, ipoffset; ipbase=ipbase, triple = triple_for_sess(frame.session))
    catch e
        warn("Failed to obtain instructions from object files ($e). Incorrect unwind info?")
        # This could have failed for a variety of reasons (missing unwind info,
        # self modifying code, etc). If so, get the instructions directly
        # from the target
        insts = NativeDebugger.load(session, NativeDebugger.RemotePtr{UInt8}(x.ip), 40)
        ipoffset = 0
        disasm_around_ip(io, insts, ipoffset; ipbase=ipbase, triple = triple_for_sess(state.top_interp.session))
    end
    return 0
end


#=
function DebuggerFramework.execute_command(state, stack, ::Val{:disas}, command)
    parts = split(command, ' ')
    stacktop = 0
    if length(parts) > 1
        ip = parse(Int, parts[2], 16)
    else
        x = isa(stack, NativeDebugger.NativeStack) ? stack.stack[end] : stack
        stacktop = (x.stacktop?0:1); ip = x.ip
    end
    base, loc, insts = get_insts(state.top_interp.session, state.top_interp.modules, ip)
    disasm_around_ip(STDOUT, insts, UInt64(ip-loc-base-stacktop);
        ipbase=base+loc, circular = false, triple = triple_for_sess(state.top_interp.session))
    return false
end

task_single_step!(timeline) = NativeDebugger.single_step!(timeline)

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.NativeStack,NativeDebugger.CStackFrame}, ::Val{:si}, command)
    task_single_step!(state.top_interp.session)
    update_stack_same_frame!(state)
    return true
end

function compute_current_line_range(state, stack)
    mod, base, ip = NativeDebugger.modbaseip_for_stack(state, stack)
    linetab, lip = NativeDebugger.obtain_linetable(state, stack)
    sm = start(linetab)
    local current_entry
    local newentry
    # Start by finding the entry that we're in
    while true
        newentry, sm = next(linetab, sm)
        newentry.address > lip && break
        current_entry = newentry
    end
    range = origrange = current_entry.address:(newentry.address-1)
    # Merge any subsequent entries at the same line
    while newentry.line == current_entry.line
        newentry, sm = next(linetab, sm)
        range = first(origrange):(newentry.address-1)
    end
    range += UInt64(ip-lip)
    range
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.NativeStack,NativeDebugger.CStackFrame}, ::Val{:n}, command)
    session = state.top_interp.session
    range = compute_current_line_range(state, stack)
    step_over(session, range)
    update_stack_same_frame!(state)
    return true
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.NativeStack,NativeDebugger.CStackFrame}, ::Val{:ip}, command)
    x = isa(stack, NativeDebugger.NativeStack) ? stack.stack[end] : stack
    println(x.ip)
    return false
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.NativeStack,NativeDebugger.CStackFrame}, ::Val{:ip}, command)
    session = state.top_interp.session
    modules = state.top_interp.modules
    found, symb = NativeDebugger.Unwinder.symbolicate(session, modules,
      parse(UInt64, split(command,' ')[2][3:end], 16))
    symb = demangle(symb)
    !found && (symb = "Most likely $symb")
    println(symb)
    return false
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.NativeStack,NativeDebugger.CStackFrame}, ::Val{:nb}, command)
    session = state.top_interp.session
    # First determine the ip of the next branch
    x = isa(stack, NativeDebugger.NativeStack) ? stack.stack[end] : stack
    base, loc, insts = get_insts(session, state.top_interp.modules, x.ip)
    ctx = DisAsmContext()
    Offset = UInt(x.ip - loc - base)
    branchip = 0
    while Offset <= sizeof(insts)
        (Inst, InstSize) = getInstruction(insts, Offset; ctx = ctx)
        if mayAffectControlFlow(Inst,ctx)
            branchip = base + loc + Offset
            break
        end
        Offset += InstSize
        free(Inst)
    end
    @assert branchip != 0
    bp = NativeDebugger.breakpoint(session, branchip)
    task_step_until_bkpt!(session)
    NativeDebugger.disable(bp)
    update_stack_same_frame!(state)
    return true
end

#cxx"""#include <cxxabi.h>"""
function demangle(name)
    return name
    startswith(name,"_Z") || return name
    status = Ref{Cint}()
    bufsize = Ref{Csize_t}(0)
    str = icxx"""
        abi::__cxa_demangle($(pointer(name)),nullptr,
        &$bufsize, &$status);
    """
    @assert status[] == 0
    ret = unsafe_string(str)
    Libc.free(str)
    ret
end


function symbolicate_frame(session, modules, x)
    found = false
    symb = "Unknown Function"
    try
        found, symb = NativeDebugger.Unwinder.symbolicate(session, modules, UInt64(x.ip))
        symb = demangle(symb)
        !found && (symb = "Most likely $symb")
    catch err
        (!isa(err, ErrorException) || !contains(err.msg, "found")) && rethrow(err)
    end
    found, symb
end

function DebuggerFramework.print_frame(state, io, num, x::NativeDebugger.CStackFrame)
    session = state.top_interp.session
    modules = state.top_interp.modules
    print(io, "[$num] ")
    found, symb = symbolicate_frame(session, modules, x)
    print(io, symb, " ")
    if x.line != 0
      print(io, " at ",x.file,":",x.line)
    end
    println(io)
end

function DebuggerFramework.execute_command(state, stack, ::Val{:c}, command)
    try
        NativeDebugger.continue!(state.top_interp.session; only_current_tgid = true)
    catch err
        !isa(err, InterruptException) && rethrow(err)
    end
    update_stack!(state)
    return true
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.CStackFrame,NativeDebugger.NativeStack}, ::Val{:reg}, command)
    ns = state.top_interp
    @assert isa(ns, NativeDebugger.NativeStack)
    RC = ns.RCs[end-(state.level-1)]
    regname = Symbol(split(command,' ')[2])
    inverse_map = isa(NativeDebugger.getarch(state.top_interp.session),NativeDebugger.X86_64.X86_64Arch) ?
        NativeDebugger.X86_64.inverse_dwarf : NativeDebugger.X86_32.inverse_dwarf
    if !haskey(inverse_map, regname)
        print_with_color(:red, STDOUT, "No such register\n")
        return false
    end
    show(UInt(NativeDebugger.get_dwarf(RC, inverse_map[regname])))
    println(); println()
    return false
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.CStackFrame,NativeDebugger.NativeStack}, ::Val{:regs}, command)
    ns = state.top_interp
    @assert isa(ns, NativeDebugger.NativeStack)
    RC = ns.RCs[end-(state.level-1)]
    show(STDOUT, RC)
    println(); println()
    return false
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.CStackFrame,NativeDebugger.NativeStack}, ::Val{:unwind}, command)
    ns = state.top_interp
    newRC = NativeDebugger.Unwinder.unwind_step(ns.session, ns.modules, ns.RCs[end-(state.level-1)];
      allow_frame_based = false, stacktop=ns.stack[end-(state.level-1)].stacktop)[2]
    @show newRC
    return false
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.CStackFrame,NativeDebugger.NativeStack}, ::Val{:symbolicate}, command)
    session = state.top_interp.session
    modules = state.top_interp.modules
    x = isa(stack, NativeDebugger.NativeStack) ? stack.stack[end] : stack
    approximate, name = NativeDebugger.Unwinder.symbolicate(session, modules, UInt64(x.ip))
    name = demangle(name)
    println(approximate ? "Most likely " : "", name)
    return false
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.CStackFrame,NativeDebugger.NativeStack}, ::Val{:modules}, command)
    modules = state.top_interp.modules
    modules = sort(collect(modules), by = x->x[1])
    for (base, mod) in modules
        show(UInt64(base)); print('-'); show(UInt64(base)+mod.sz); println()
    end
    return false
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.CStackFrame,NativeDebugger.NativeStack}, ::Val{:finish}, command)
    ns = state.top_interp
    session = state.top_interp.session
    @assert isa(ns, NativeDebugger.NativeStack)
    parentRC = ns.RCs[end-(state.level)]
    theip = NativeDebugger.ip(parentRC)
    step_to_address(session, theip)
    update_stack!(state)
    return true
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.CStackFrame,NativeDebugger.NativeStack}, ::Val{:b}, command)
    session = state.top_interp.session
    modules = state.top_interp.modules
    symbol = split(command,' ')[2]
    if startswith(symbol, "0x")
      addr = parse(UInt64, symbol[3:end], 16)
      bp = NativeDebugger.breakpoint(session, addr)
    else
      bp = NativeDebugger.breakpoint(session, modules, symbol)
    end
    show(bp)
    return false
end


function dwarf2Cxx(dbgs, dwarfT)
    if DWARF.tag(dwarfT) == DWARF.DW_TAG_pointer_type || 
            DWARF.tag(dwarfT) == DWARF.DW_TAG_array_type
        dwarfT = get(DWARF.extract_attribute(dwarfT,DWARF.DW_AT_type))
        return Cxx.pointerTo(Cxx.instance(RemoteClang), dwarf2Cxx(dbgs, dwarfT.value))
    else
        name = DWARF.extract_attribute(dwarfT,DWARF.DW_AT_name)
        name = bytestring(get(name).value,StrTab(dbgs.debug_str))
        return cxxparse(Cxx.instance(RemoteClang),name,true)
    end
end

function iterate_frame_variables(state, stack, found_cb, not_found_cb)
    mod, base, theip = NativeDebugger.modbaseip_for_stack(state, stack)
    lip = NativeDebugger.compute_ip(NativeDebugger.dhandle(mod),base,theip)
    dbgs = debugsections(NativeDebugger.dhandle(mod))
    ns = state.top_interp
    @assert isa(ns, NativeDebugger.NativeStack)
    RC = ns.RCs[end-(state.level-1)]
    
    NativeDebugger.iterate_variables(RC, found_cb, not_found_cb, dbgs, lip)
end
    

function realize_remote_value(T, val, getreg)
    if isa(val, DWARF.Expressions.MemoryLocation)
        val = NativeDebugger.load(timeline, RemotePtr{T}(val.i))
    elseif isa(val, DWARF.Expressions.RegisterLocation)
        val = reinterpret(T, [getreg(val.i)])[]
    end
    val
end

function DebuggerFramework.execute_command(state, stack::Union{NativeDebugger.CStackFrame,NativeDebugger.NativeStack}, ::Val{:vars}, command)
    function found_cb(dbgs, vardie, getreg, name, val)
        dwarfT = get(DWARF.extract_attribute(vardie,DWARF.DW_AT_type))
        try 
            T = Cxx.juliatype(dwarf2Cxx(dbgs, dwarfT.value))
            val = realize_remote_value(T, val, getreg)
        end
        @show (name, val)
    end
    iterate_frame_variables(state, stack, found_cb, (dbgs, vardie, name)->nothing)
    
    return false
end
=#
