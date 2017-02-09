__precompile__(false)
module NativeDebugger
    using DebuggerFramework

    include("remote.jl")
    include("registers.jl")
    include("x86_64/registers.jl")
    include("x86_32/registers.jl")
    include("win64seh.jl")
    include("modules.jl")
    include("unwind.jl")
    include("ptrace.jl")
    include("disassembler.jl")

    abstract NativeStackFrame

    "A machine-ABI compliant stack frame on the actual stack"
    immutable PhysicalStackFrame <: NativeStackFrame
        RC
        session
        modules
        stacktop::Bool
    end
    ip(frame::PhysicalStackFrame) = ip(frame.RC)
    isstacktop(frame::PhysicalStackFrame) = frame.stacktop
    
    immutable VirtualStackFrame <: NativeStackFrame
        phys::PhysicalStackFrame
        level::Int
    end

    immutable StackIterator
        topRC
        session
        modules
        allow_bad_unwind::Bool
        StackIterator(topRC, session, modules) = new(topRC, session, modules, true)
    end
    
    Base.start(it::StackIterator) = it.topRC
    Base.done(it::StackIterator, state) = state === nothing
    function Base.next(it::StackIterator, state)
        @show "hello"
        @assert state !== nothing
        try
            success, newRC = Unwinder.unwind_step(it.session, it.modules, state)
        catch e
            !it.allow_bad_unwind && rethrow(e)
            success, newRC = false, state
        end
        (PhysicalStackFrame(state, it.session, it.modules, state == it.topRC),
          success ? newRC : nothing)
    end
    Base.iteratorsize(::Type{StackIterator}) = Base.SizeUnknown()
    

    using .Registers
    using .Registers: ip, get_dwarf

    function breakpoint
    end
    
    function enable
    end
    
    function disable
    end
    
    function print_location
    end
  
    abstract LocationSource
    immutable Location
        vm
        addr::UInt64
    end
    type Breakpoint
        active_locations::Vector{Location}
        inactive_locations::Vector{Location}
        sources::Vector{LocationSource}
        disable_new::Bool
        conditions::Vector{Any}
    end
    Breakpoint(locations::Vector{Location}) = Breakpoint(locations, Location[], LocationSource[], false, Any[])
    Breakpoint() = Breakpoint(Location[], Location[], LocationSource[], false, Any[])
  
    include("interface.jl")
  
end # module
