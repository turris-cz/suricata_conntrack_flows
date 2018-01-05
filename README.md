# Suricata_conntrack_flows

##### Background

Suricata with bypass (default settings on our router) doesn't provide counters for flows - when bypassed, flows are not even delivered to Suricata, so it can't. This improves performance a lot, but we still want that data. Workaround is to get these information from conntrack.

##### This repo

This repository contains simple script, that combines information from Suricata and conntrack and **outputs flow information with the right counters**.
