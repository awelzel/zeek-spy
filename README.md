# zeek-spy - Sampling Profiler for Zeek

**experimental - proof of concept**

[![Build Status](https://travis-ci.org/awelzel/zeek-spy.svg?branch=master)](https://travis-ci.org/awelzel/zeek-spy)

## How it works

`zeek-spy` attaches to a running `zeek` process using `ptrace(2)` and reads
the `call_stack` and `g_frame_stack` memory.

Using the referenced `CallInfo`, `Func`, `Stmt`, `Frame` and `Location` objects,
a sample (call stack) of Zeek script land is created including function names,
filenames and line numbers.

Upon termination `zeek-spy` writes all samples as gziped "profile.proto" file.
This file can then be analyzed with [pprof][1].

The idea was prompted by [rbspy][2] and [py-spy][3].

## Compatibility / Limitations

This was developed against Zeek 3.0.1, compiled with GCC 8.3.0 on `x86_64`.
Concretely, the [binary Zeek packages][4] for Debian 10 in version 3.0.1
should be working.

Anything else will (very very) likely not work. The current code uses
hard-coded offsets related to the memory layout of `std::vector`, `std::string`,
`CallInfo`, `Frame` and more. They may be just wrong for a different Zeek
and/or compiler version. C++ does not make this easier, either.

Memory locations and offsets were determined with `elf`, `gdb`, `dwarfdump`
and sometimes just counting.


## Usage

### Sample profile

To look at a provided profile inside this repo.

    $ pprof -http=localhost:9999 -ignore=empty_call_stack -trim=false -filefunctions ./sample-profiles/macdc2012.pb.gz

### Profiling a running `zeek` process

This assumes `pgrep` finds just a single process.

    $ sudo zeek-spy -pid $(pgrep zeek) -hz 250 -profile ./zeek.pb.gz
    ...
    Ctrl+C
    
    # zeek.pb.gz is in profile.proto format (https://github.com/google/pprof/tree/master/proto)

    # Analyze with pprof
    $ pprof -ignore=empty_call_stack -trim=false -lines  ./zeek.pb.gz
    Type: samples
    Time: Jan 30, 2020 at 1:35pm (CET)
    Duration: 31.55s, Total samples = 7661
    Entering interactive mode (type "help" for commands, "o" for options)
    Active filters:
       ignore=empty_call_stack
    Showing nodes accounting for 4036, 52.68% of 7661 total
          flat  flat%   sum%        cum   cum%
           549  7.17%  7.17%        549  7.17%  Log::__write
           436  5.69% 12.86%        436  5.69%  sha256_hash /home/awelzel/projects/zeek/scripts/base/init-bare.zeek:5171
           269  3.51% 16.37%        269  3.51%  sha1_hash /home/awelzel/projects/zeek/scripts/base/init-bare.zeek:5171
           245  3.20% 19.57%        245  3.20%  md5_hash /home/awelzel/projects/zeek/scripts/base/init-bare.zeek:5171
           132  1.72% 21.29%        132  1.72%  connection_state_remove /home/awelzel/projects/zeek/scripts/base/protocols/http/main.zeek:329
           119  1.55% 22.84%        119  1.55%  connection_state_remove /home/awelzel/projects/zeek/scripts/base/protocols/sip/main.zeek:296
            83  1.08% 23.93%         83  1.08%  schedule_me scripts/slow_dns.zeek:32
            78  1.02% 24.94%         78  1.02%  connection_state_remove /home/awelzel/projects/zeek/scripts/base/protocols/dce-rpc/main.zeek:218
            73  0.95% 25.90%        356  4.65%  dns_request scripts/slow_dns.zeek:12
            72  0.94% 26.84%         72  0.94%  connection_state_remove /home/awelzel/projects/zeek/scripts/base/protocols/ftp/main.zeek:290
            60  0.78% 27.62%         60  0.78%  connection_state_remove /home/awelzel/projects/zeek/scripts/base/protocols/socks/main.zeek:119
            ...


    # Or browse the profile interactively in a browser
    $ pprof -http=localhost:9999 -ignore=empty_call_stack -trim=false -filefunctions ./zeek.pb.gz


### Performance Impact

The `zeek` process is stopped while `zeek-spy` takes a sample. A separate
`ptrace-attach` happens for every sample. Performance may degrade for very
high and possibly moderate sampling frequencies. The default is 100 hz.

`zeek-spy` outputs an estimation of the overhead while running
(see the `-stats` option).

`zeek-spy` is very performance naive, too. There are various ways to improve
sampling performance. Starting from caching "constant" memory locations,
switching to `process_vm_readv(2)` and most likely many Go specific tweaks.


### Profiling processing of a PCAP file

This is a bit of a crutch and basically the same as above, but nicer for testing:

    $ timeout 10 /opt/zeek/bin/zeek -r ./pcaps/maccdc2012_00000.pcap & sleep 0.2 && ./zeek-spy -pid $(pgrep zeek) -hz 250 -profile ./macdc2012.pb.gz -stats 1s
    2020/02/22 16:33:40 Using pid=31072, hz=250 period=4ms (4.000000 ms) profile=./zeek.pb.gz
    2020/02/22 16:33:40 Profiling ZeekProcess{Pid=31072, Exe=/opt/zeek/bin/zeek, LoadAddr=0x55f9a6665000, CallStackAddr=0x55f9a73e2680, FrameStackAddr=0x55f9a73e2470 VersionAddr=0x55f9a73dd330}
    2020/02/22 16:33:40 Found Zeek version '3.0.1'
    2020/02/22 16:33:41 [STATS] elapsed=1.00s samples=134 (250 total) skipped=0 frequency=250.0hz overhead=2.76% (27.578542ms)
    2020/02/22 16:33:42 [STATS] elapsed=2.00s samples=337 (500 total) skipped=0 frequency=250.0hz overhead=3.49% (34.902129ms)
    2020/02/22 16:33:43 [STATS] elapsed=3.00s samples=560 (750 total) skipped=0 frequency=250.0hz overhead=4.08% (40.829118ms)
    ...
    1331901122.870000 received termination signal
    2020/02/22 16:33:50 [STATS] elapsed=10.00s samples=2097 (2500 total) skipped=0 frequency=250.0hz overhead=4.48% (44.825587ms)
    2020/02/22 16:33:50 [WARN] wait() failed for 31072: process exited
    2020/02/22 16:33:50 [WARN] Could not detach from process: no such process
    2020/02/22 16:33:50 [WARN] Failed to spy, exiting (process exited)
    2020/02/22 16:33:50 Writing protobuf...
    2020/02/22 16:33:50 Done.


### pprof flags

As event handlers all have the same function name and do not live in a module,
depending on the `granularity` setting of `pprof` the output will vary.

Using `lines` or `filefunctions` gives reasonable results.

    $ pprof -ignore=empty_call_stack -trim=false -lines   ./zeek.pb.gz

The `-ignore=empty_call_stack` is used to filter out all samples where
the `call_stack` was empty. This is useful when there's only very little
traffic and the `empty_call_stack` samples dominate the profile.


[1]: https://github.com/google/pprof
[2]: https://github.com/rbspy/rbspy
[3]: https://github.com/benfred/py-spy
[4]: https://software.opensuse.org//download.html?project=security%3Azeek&package=zeek
