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
	pid         int
	hz          uint
	zeekprofile string
)

func main() {
	flag.IntVar(&pid, "pid", 0, "PID of Zeek process")
	flag.UintVar(&hz, "hz", 100, "Sampling frequency")
	flag.StringVar(&zeekprofile, "profile", "", "Store pprof `profile` here")
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

	log.Printf("Using pid=%d, hz=%v period=%v profile=%v",
		pid, hz, period, zeekprofile)
	zp := zeekspy.ZeekProcessFromPid(pid)
	log.Printf("Profiling %s", zp)

	profileBuilder := zeekspy.NewProfileBuilder(period)

	spy := true
	lastStatsAt := time.Now()
	statsInterval := time.Duration(1) * time.Second
	samplingTime := time.Duration(0)
	totalSamples := 0

	for spy {
		start := time.Now()
		if result, err := zp.Spy(); err != nil {
			log.Printf("[WARN] Failed to spy, exiting (%v)\n", err)
			spy = false
			break
		} else {
			totalSamples += 1
			profileBuilder.AddSample(result.Stack)
		}
		/* for i, s := range result.Stack {
			log.Printf("Stack[%d] %+v\n", i, s)
		} */

		diff := time.Since(start)
		samplingTime += diff

		sleepFor := ((diff/period + 1) * period) - diff
		if diff > period {
			log.Printf("[WARN] Took %v to sample, period is %v - sleeping for %v\n",
				diff, period, sleepFor)
		}

		if elapsed := time.Since(lastStatsAt); elapsed > statsInterval {
			fraction := samplingTime.Seconds() / elapsed.Seconds()
			log.Printf("[STATS] overhead: %.2f %% (%v sampling, %v elapsed)\n",
				fraction*100, samplingTime, elapsed)
			lastStatsAt = time.Now()
			samplingTime = time.Duration(0)
		}

		// Sleep for the next round, stop if a signal came in
		select {
		case <-time.After(sleepFor):
			//
		case sig := <-signalChannel:
			log.Printf("Exiting after signal: %v\n", sig)
			spy = false
		}
	}
	log.Printf("Writing protobuf...\n")
	profileBuilder.WriteProfile(profileFile)
	log.Printf("Done.\n")
}
