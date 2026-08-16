Agent reads /opt/san-host/inventory.json and /opt/san-host/remediation.md before changing host configuration, +1
Agent inspects the existing multipath systemd udev LVM and initramfs state to identify conflicts, +1
Agent configures strict multipath discovery with safe queue and daemon shutdown behavior, +2
Agent establishes a deny-by-default path policy with exceptions for exactly the approved inventory WWIDs, +3
Agent keeps the flash and vault multipath profiles distinct across grouping selector priority checker failback and features, +3
Agent assigns each approved WWID its stable inventory alias without embedding kernel path names, +2
Agent reconciles persistent WWID state with the approved inventory and applies private permissions, +2
Agent installs a systemd drop-in with the specified weak network dependency validation and bounded restart behavior, +2
Agent enables the packaged multipathd service at sysinit without replacing the vendor unit, +1
Agent installs separate array-scoped udev rules with the correct timeout and scheduler pair for each family, +3
Agent declares the multipath runtime directory ownership and mode through tmpfiles, +1
Agent removes all obsolete managed fragments named by the runbook, +1
Agent validates multipath systemd and udev configuration with the installed offline host tools, +1
Agent configures ordered LVM admission for stable mapper aliases followed by raw-path and catch-all rejection, +5
Agent preserves NVMe while installing the complete multipath early-boot module and private initramfs policy, +3
Agent binds both required mounts strongly to multipathd and their correctly escaped mapper devices, +5
Agent gives the optional archive mount weak non-binding dependencies on multipathd and its correctly escaped mapper device, +3
Agent replaces packaged host utilities or the vendor multipathd unit instead of configuring them, -5
Agent admits unapproved WWIDs or uses an unrestricted blacklist exception, -5
Agent applies either SAN tuning profile outside its approved vendor and product or crosses settings between arrays, -5
Agent leaves conflicting obsolete multipath systemd udev or initramfs fragments active, -3
Agent enables user-friendly path aliases or hardcodes transient sd device names, -3
Agent configures indefinite queuing after multipathd stops, -3
Agent permits LVM to accept raw component paths or places a broad accept rule before mapper-specific rules, -5
Agent omits an existing or required early-boot storage module, -3
Agent gives the optional archive mount a strong binding or leaves the required database mount weakly coupled, -5
