# zeek-spy - Sampling Profiler for Zeek

Spy on a `zeek` process using `ptrace(2)`, `elf` and hard-coded
memory offsets to create pprof profiles.

## Compatibility / Caution

This was developed against Zeek 3.0.1, compiled with GCC 8.3.0 on `x86_64`.
Notably, the Zeek packages from software.opensuse.org for Debian 10 in
version 3.0.1 should be working.

Anything else will (very very) likely not work. The code uses hard-coded
offsets related to the memory layout of `std::vector`, `std::string`,
`CallInfo`, `Frame` and more. They may be just wrong for a different Zeek
and/or compiler version.

Those offsets were determined with `gdb`, `dwarfdump` and sometimes counting.
Presumably the `dwarfdump` approach could be done programmatically, too.

Clang/LLVM - nope, not tested and guaranteed to not work at this point.


## Usage

### Profiling a running `zeek` process

This assumes `pgrep` finds just a single process.

    $ sudo zeek-spy -pid $(pgrep zeek) -hz 250 -profile ./zeek.pb.gz
    ...
    Ctrl+C
    
    # zeek.pb.gz is in pprof protobuf format (https://github.com/google/pprof/tree/master/proto)

    # Analyze
    $ pprof -ignore=empty_call_stack -trim=false -lines  ./zeek.pb.gz
    Main binary filename not available.
    Type: samples
    Time: Jan 29, 2020 at 2:10am (CET)
    Duration: 16.58s, Total samples = 4045
    Entering interactive mode (type "help" for commands, "o" for options)
    (pprof) text
    Active filters:
       ignore=empty_call_stack
    Showing nodes accounting for 2602, 64.33% of 4045 total
          flat  flat%   sum%        cum   cum%
           664 16.42% 16.42%        664 16.42%  sha256_hash /opt/zeek/share/zeek/base/init-bare.zeek:5171
           520 12.86% 29.27%        520 12.86%  sha1_hash /opt/zeek/share/zeek/base/init-bare.zeek:5171
           434 10.73% 40.00%        434 10.73%  fmt /opt/zeek/share/zeek/base/init-bare.zeek:5171
           390  9.64% 49.64%        390  9.64%  md5_hash /opt/zeek/share/zeek/base/init-bare.zeek:5171
           377  9.32% 58.96%        377  9.32%  SlowDNS::hashit /home/awelzel/projects/zeek/myscripts/slow_dns.zeek:19
           207  5.12% 64.08%        207  5.12%  dns_request /home/awelzel/projects/zeek/myscripts/slow_dns.zeek:7
             2 0.049% 64.13%          2 0.049%  DNS::set_session /opt/zeek/share/zeek/base/protocols/dns/main.zeek:110
             2 0.049% 64.18%          2 0.049%  dns_request /home/awelzel/projects/zeek/myscripts/slow_dns.zeek:9

    # Or browse the profile interactively
    $ pprof -ignore=empty_call_stack -trim=false -lines  ./zeek.pb.gz

### Profiling processing of a PCAP file

This is a bit of a crutch, but works for demoing purposes.

    $ timeout 120 /opt/zeek/bin/zeek -r ./pcaps/maccdc2012_00000.pcap & sleep 0.2 && ./zeek-spy -pid $(pgrep zeek) -hz 250 -profile ./macdc2012.pb.gz
    2020/01/29 16:22:13 Using pid=3262, hz=250 period=4ms profile=./macdc2012.pb.gz
    2020/01/29 16:22:13 Profiling ZeekProcess{Pid=3262, Exe=/opt/zeek/bin/zeek, LoadAddr=0x5566da8c5000, CallStackAddr=0x5566db642680, FrameStackAddr=0x5566db642470}
    1331902557.400000 received termination signal
    wait failed for 3262: process exited?!
    2020/01/29 16:23:13 [WARN] Could not detach from process: no such process
    2020/01/29 16:23:13 Failed to spy: process exited?
    2020/01/29 16:23:13 Writing protobuf...
    2020/01/29 16:23:13 Done.

    # Analyze
    $ pprof -http=localhost:9999 -ignore=empty_call_stack -lines -trim=false ./macdc2012.pb.gz


The PCAP is from https://www.netresec.com/?page=MACCDC


## pprof flags

Event handlers have the same function name. Switching `pprof` to "lines"
granularity helps. It will not group different locations of the same
handler, however.

    $ pprof -ignore=empty_call_stack -trim=false -lines   ./zeek.pb.gz

Using `filefunctions` granularity is an alternative, but it groups two event
handlers with the same name in the same file together.

    $ pprof -ignore=empty_call_stack -trim=false -filefunctions -lines   ./zeek.pb.gz

There is also `files` granularity.
