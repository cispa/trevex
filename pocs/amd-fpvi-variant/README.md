# Vector Value Injection (VVI)

# Denoise By Disabling Prefetchers
This step is not required but makes the PoC less noisy
Execute the following
```
sudo wrmsr -a 0xc0011022 $(printf "0x%X" $(( $(sudo rdmsr -u 0xc0011022) | 0xa000 )))
sudo wrmsr -a 0xc001102b $(printf "0x%X" $(( $(sudo rdmsr -u 0xc001102b) | 0x70008 )))
sudo wrmsr -a 0xc0000108 0x2f || true
```

# Build the PoC
- Execute `make`

# Executing the PoC
- Just execute it by `./main`

## Expected Output:
The output should look like this:
```
--------------------
Result: 0x0 (100 times)
Result: 0xac (100 times)
--------------------
```

The PoC encodes the (potentially) transient result of a `mulpd` instruction.
Architecturally we expect the value `0x0` but instead the value `0xac` comes back as well.
To verify the architectural result, one can uncomment the macro `ADD_FENCE`.
As this does not require denormal values to be triggered (in contrast to FPVI) but seems to require vector instructions (according to our experiments), we label this vulnerability VVI.
For our tests it looks like setting the FTZ *and* DAZ bits in MXCSR stops the leakage (see `main`).