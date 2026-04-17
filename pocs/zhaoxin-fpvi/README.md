# Floating Point Value Injection

## Build the PoC
- Execute `make`

## Executing the PoC
- Just execute it by `./main`

### Expected Output:
The output should look like this:
```
--------------------
0x12 -> 100
0x32 -> 100
--------------------
```

The PoC encodes the (potentially) transient result of a `subpd` instruction.
Architecturally, we expect the value `0x32` but instead the value `0x22` comes back as well.
To verify the architectural result, one can uncomment the macro `ADD_FENCE`.
According to our initial tests, it looks like one the input operands of the instruction must be a denormal value to trigger the forwarding of incorrect data.
Note that while this PoC does demonstrate the attack potential, previous research has already shown the security impact that transiently injected value can have.

As this requires a denormal values to be triggered, we hypothesize that this vulnerability is an instance of FPVI on Zhaoxin CPUs.
For our tests, it looks like setting the FTZ *and* DAZ bits in MXCSR stops the leakage (see `main`).
