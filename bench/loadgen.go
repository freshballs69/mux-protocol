// loadgen — a concurrency load generator with latency statistics.
//
//	go run loadgen.go -target host:port -c 50000 -d 15s
//
// Spawns -c goroutines; each repeatedly dials the target, sends one HTTP GET
// (Connection: close), reads the whole response, and records the round-trip,
// until -d elapses. Prints throughput and latency percentiles. Goroutines make
// 50k concurrency cheap; run it in a Linux container with a high nofile limit
// to push past the host's per-process fd cap.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const nb = 256 // latency histogram buckets (log scale, factor 2^(1/8) per bucket)

func bucket(d time.Duration) int {
	us := d.Microseconds()
	if us < 1 {
		us = 1
	}
	b := int(math.Log2(float64(us)) * 8)
	if b < 0 {
		b = 0
	}
	if b >= nb {
		b = nb - 1
	}
	return b
}

func bucketUS(b int) float64 { return math.Pow(2, float64(b)/8) }

func main() {
	target := flag.String("target", "127.0.0.1:8080", "host:port")
	conc := flag.Int("c", 1000, "concurrency (goroutines / open connections)")
	dur := flag.Duration("d", 15*time.Second, "test duration")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	path := flag.String("path", "/", "request path")
	flag.Parse()

	req := []byte("GET " + *path + " HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n")
	deadline := time.Now().Add(*dur)

	var success, errors, bytesIn int64
	hists := make([][nb]int64, *conc)
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func(h *[nb]int64) {
			defer wg.Done()
			buf := make([]byte, 16384)
			for time.Now().Before(deadline) {
				t0 := time.Now()
				conn, err := net.DialTimeout("tcp", *target, *timeout)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				conn.SetDeadline(time.Now().Add(*timeout))
				if _, err := conn.Write(req); err != nil {
					atomic.AddInt64(&errors, 1)
					conn.Close()
					continue
				}
				ok, total := false, 0
				for {
					n, e := conn.Read(buf)
					if n > 0 {
						total += n
						if !ok && bytes.Contains(buf[:n], []byte(" 200 ")) {
							ok = true
						}
					}
					if e != nil {
						break
					}
				}
				conn.Close()
				if ok && total > 0 {
					atomic.AddInt64(&success, 1)
					atomic.AddInt64(&bytesIn, int64(total))
					h[bucket(time.Since(t0))]++
				} else {
					atomic.AddInt64(&errors, 1)
				}
			}
		}(&hists[i])
	}
	wg.Wait()
	elapsed := time.Since(start)

	// merge histograms
	var merged [nb]int64
	var totalSamples int64
	for i := range hists {
		for b := 0; b < nb; b++ {
			merged[b] += hists[i][b]
			totalSamples += hists[i][b]
		}
	}
	pct := func(p float64) float64 {
		target := int64(float64(totalSamples) * p)
		var cum int64
		for b := 0; b < nb; b++ {
			cum += merged[b]
			if cum >= target {
				return bucketUS(b) / 1000.0 // ms
			}
		}
		return bucketUS(nb-1) / 1000.0
	}

	suc := atomic.LoadInt64(&success)
	errs := atomic.LoadInt64(&errors)
	secs := elapsed.Seconds()
	fmt.Printf("\n================ loadgen ================\n")
	fmt.Printf("target          %s\n", *target)
	fmt.Printf("concurrency     %d\n", *conc)
	fmt.Printf("duration        %.1fs\n", secs)
	fmt.Printf("completed       %d  (%.0f req/s)\n", suc, float64(suc)/secs)
	fmt.Printf("errors          %d  (%.2f%%)\n", errs, 100*float64(errs)/math.Max(1, float64(suc+errs)))
	fmt.Printf("throughput      %.1f MB/s\n", float64(atomic.LoadInt64(&bytesIn))/1e6/secs)
	fmt.Printf("latency  p50    %.2f ms\n", pct(0.50))
	fmt.Printf("         p90    %.2f ms\n", pct(0.90))
	fmt.Printf("         p99    %.2f ms\n", pct(0.99))
	fmt.Printf("         max    ~%.0f ms\n", pct(0.999))
	fmt.Printf("=========================================\n")
}
