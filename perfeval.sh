# Start your Zig HTTP server with perf recording
sudo perf record -F 99 -g -p $(ps -aux | grep -i zig | grep -i "vedant_stock_exchange" | awk '{print $2}') -o perf.data

# In another terminal, run wrk to generate load
wrk -t12 -c400 -d30s http://localhost:3000/
# This uses 12 threads, 400 connections, for 30 seconds

# After the benchmark is complete, stop perf recording with Ctrl+C
# Convert perf data to readable format
sudo perf script -i perf.data > perf.out
../FlameGraph/stackcollapse-perf.pl perf.out > perf.folded
../FlameGraph/flamegraph.pl perf.folded > flamegraph.svg
