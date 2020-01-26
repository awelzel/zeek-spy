# zeek-spy

Spy on a `zeek` process using `ptrace(2)`, `elf` and hard-coded memory
offsets to create pprof profiles of Zeek script land.

## Compatibility / Caution

This was developed against Zeek 3.0.1, compiled with GCC 8.3.0 on `x86_64`.
Notably, the Zeek packages from software.opensuse.org for Debian 10 in
version 3.0.1 should be working.

Anything else will (very very) likely not work. The code uses hard-coded
offsets related to the memory layout of `std::vector`, `std::string`,
`CallInfo`, `Frame` and more. They may be just wrong for a different Zeek
and/or compiler version.

Those offsets were determined with `gdb`, `dwarfdump` and sometimes counting.
Presumably the `dwarfdump` approach could be done programmatically.

Clang/LLVM - nope, not tested and guaranteed to not work at this point.


## Usage and Example

    $ zeek-spy -pid $(pgrep zeek) -hz 250 -profile ./zeek.pb.gz
    ...
    Ctrl+C
    
    # zeek.pb.gz is in pprof protobuf format (https://github.com/google/pprof/tree/master/proto)

    # Analyze
    $ pprof -ignore=empty_call_stack -trim=false -lines  ./zeek.pb.gz
    (pprof) text
    Active filters:
       ignore=empty_call_stack
    Showing nodes accounting for 9031, 68.29% of 13225 total
    Dropped 81 nodes (cum <= 66)
          flat  flat%   sum%        cum   cum%
          4997 37.78% 37.78%       4997 37.78%  sha1_hash /opt/zeek/share/zeek/base/init-bare.zeek:5171
          1626 12.29% 50.08%       1626 12.29%  MyDNS::hashit /home/awelzel/projects/zeek/myscripts/slow_dns.zeek:20
          1525 11.53% 61.61%       1525 11.53%  fmt /opt/zeek/share/zeek/base/init-bare.zeek:5171
           877  6.63% 68.24%        877  6.63%  dns_request /home/awelzel/projects/zeek/myscripts/slow_dns.zeek:7
             4  0.03% 68.27%       1471 11.12%  schedule_me /home/awelzel/projects/zeek/myscripts/slow_dns.zeek:29
             2 0.015% 68.29%       6678 50.50%  dns_request /home/awelzel/projects/zeek/myscripts/slow_dns.zeek:26

    # Or browse the profile interactively
    $ pprof -ignore=empty_call_stack -trim=false -lines  ./zeek.pb.gz


## pprof flags

Event handlers have the same function name. Switching `pprof` to "lines"
granularity helps. It will not group different locations of the same
handler, however.

    $ pprof -ignore=empty_call_stack -trim=false -lines   ./zeek.pb.gz

Using `filefunctions` granularity is an alternative, but it groups two event
handlers with the same name in the same file together.

    $ pprof -ignore=empty_call_stack -trim=false -filefunctions -lines   ./zeek.pb.gz

There is also `files` granularity.
