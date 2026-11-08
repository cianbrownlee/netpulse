# Design notes

Further design decisions that are not in the README's main list.

- **One codebase, two capture systems.** Everything above the capture layer (parsing, aggregation, the classifier, the dashboard) is the same on Linux and Windows. The platform differences are how the capture filter is installed, adapter naming ("Wi-Fi" instead of `\Device\NPF_{...}`), and a few small system calls in one file.
- **DNS lookups cannot stall anything.** Reverse lookups run on worker threads with a session cache. A hung DNS server delays a name appearing, but never the statistics, and never blocks quitting.
- **Conversations instead of packets.** Flow keys are canonical, so both directions of a conversation share one entry, with byte counts per direction.

For the plan and progress, see [plan.md](plan.md). For how each performance number was measured, see [benchmarks.md](benchmarks.md).
