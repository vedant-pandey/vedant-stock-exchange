# Start your Zig HTTP server with perf recording
sudo perf record -F 99 -g -p $(pgrep your-zig-server) -o perf.data

# In another terminal, run wrk to generate load
wrk -t12 -c400 -d30s http://localhost:3000/
# This uses 12 threads, 400 connections, for 30 seconds

# After the benchmark is complete, stop perf recording with Ctrl+C
# Convert perf data to readable format
sudo perf script -i perf.data > perf.out

# Convert to folded format for flamegraph
./FlameGraph/stackcollapse-perf.pl perf.out > perf.folded

# Generate SVG flamegraph
./FlameGraph/flamegraph.pl perf.folded > flamegraph.svg
