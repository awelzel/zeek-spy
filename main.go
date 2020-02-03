package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/awelzel/zeek-spy/zeekspy"
)

func init() {
	// We are using ptrace(2) - must stick to the same thread.
	//
	// https://github.com/golang/go/issues/7699
	runtime.LockOSThread()
}

var (
	pid           int
	hz            uint
	zeekprofile   string
	debug         bool
	statsInterval time.Duration
)

func main() {
	fiveSeconds, _ := time.ParseDuration("5s")
	flag.IntVar(&pid, "pid", 0, "PID of Zeek process")
	flag.UintVar(&hz, "hz", 100, "Sampling frequency")
	flag.BoolVar(&debug, "debug", false, "Enable sample debugging")
	flag.StringVar(&zeekprofile, "profile", "", "Store pprof `profile` here")
	flag.DurationVar(&statsInterval, "stats", fiveSeconds,
		"Print stats every `interval` times.")
	flag.Parse()

	if pid == 0 || zeekprofile == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	profileFile, err := os.Create(zeekprofile)
	if err != nil {
		log.Fatal(err)
	}
	defer profileFile.Close()

	// Redirect Ctrl+C to signalChannel
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)

	period := time.Duration((1000000 / hz)) * time.Microsecond

	log.Printf("Using pid=%d, hz=%v period=%v (%.6f ms) profile=%v\n",
		pid, hz, period, period.Seconds()*1000, zeekprofile)
	zp := zeekspy.ZeekProcessFromPid(pid)
	log.Printf("Profiling %s\n", zp)
	if version, err := zp.Version(); err == nil {
		log.Printf("Found Zeek version '%s'", version)
	} else {
		log.Fatalf("Error reading version: %v", err)
	}

	profileBuilder := zeekspy.NewProfileBuilder(period)

	stopped := false
	statsSamplingTime := time.Duration(0)
	totalSamples := 0
	nonEmptySamples := 0
	totalSkipped := 0
	totalStart := time.Now()
	nextSample := totalStart
	nextStats := totalStart.Add(statsInterval)
	diff := time.Duration(0)

	for !stopped {
		start := time.Now()
		if result, err := zp.Spy(); err != nil {
			log.Printf("[WARN] Failed to spy, exiting (%v)\n", err)
			stopped = true
			break
		} else {
			diff = time.Since(start)
			totalSamples += 1
			profileBuilder.AddSample(result.Stack)
			if !result.Empty {
				nonEmptySamples = nonEmptySamples + 1
				if debug {
					for i, s := range result.Stack {
						log.Printf("Sample[%d][%d] %+v\n",
							totalSamples, i, s)
					}
				}
			}

		}

		statsSamplingTime += diff
		skippedSamples := int(diff / period)
		totalSkipped += skippedSamples
		nextSample = nextSample.Add(time.Duration(1+skippedSamples) * period)

		select {
		case <-time.After(time.Until(nextSample)):
			//
		case sig := <-signalChannel:
			log.Printf("Exiting after signal: %v\n", sig)
			stopped = true
		}

		if now := time.Now(); now.After(nextStats) {
			elapsed := now.Sub(totalStart)
			fraction := statsSamplingTime.Seconds() / statsInterval.Seconds()
			samplingRate := float64(totalSamples) / time.Since(totalStart).Seconds()

			log.Printf("[STATS] elapsed=%.2fs samples=%d (%d total) skipped=%d frequency=%.1fhz overhead=%.2f%% (%v)\n",
				elapsed.Seconds(), nonEmptySamples, totalSamples, totalSkipped,
				samplingRate, fraction*100, statsSamplingTime)
			nextStats = nextStats.Add(statsInterval)
			statsSamplingTime = time.Duration(0)
		}
	}
	log.Printf("Writing protobuf...\n")
	profileBuilder.WriteProfile(profileFile)
	log.Printf("Done.\n")
}
