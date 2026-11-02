# Test fixtures

**The JSON files in this folder are hand-made, not recorded.** They follow the
real response formats of the NVD CVE API 2.0, the FIRST EPSS API and the CISA
KEV feed, but the numbers and dates are illustrative test values, not real data
about these CVEs. (The build environment could not reach the APIs.)

To record real responses, run this once on a machine with internet access:

    python scripts/record_fixtures.py

That saves real responses into `tests/fixtures/recorded/`, and
`tests/test_recorded_fixtures.py` then checks our parsers against them. The
tests in this folder never touch the network either way.

`nmap_edge_cases.xml` is a hand-made scan file covering the edge cases
(several ports, a host with no CVEs, a host not in the assets file, old-style
vulners output and non-CVE vulners entries). It describes no real machine.
