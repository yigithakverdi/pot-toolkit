.
├── meson.build            # Build configuration (adjust targets for new structure)
├── LICENSE
├── README.md              # Updated project description, build/run instructions, new structure explanation
├── config/                # Directory for configuration files
│   └── node_config.json   # Example: Defines node role (ingress/transit/verifier), interfaces, active POT profile set name
│   └── pot_profiles/      # Directory to store POT profiles received from a Controller (e.g., via NETCONF/YANG)
│       └── profile_set_A_even.json  # Example POT profile (structure based on YANG model)
│       └── profile_set_A_odd.json   # Example corresponding odd profile
├── include/               # Public headers for libraries/modules
│   ├── common.h           # Common definitions, macros, includes (e.g., Prime type)
│   ├── dpdk_utils.h       # Headers for DPDK helper functions
│   ├── packet_utils.h     # Headers for packet parsing/manipulation
│   ├── pot.h              # Headers for core POT logic & data structures (POT-Profile, CML, RND)
│   ├── opot.h             # Optional: Headers for Ordered POT logic (masks)
│   └── crypto_utils.h     # Headers for cryptographic functions (HMAC, potentially XOR utils)
├── src/                   # Source files
│   ├── main.c             # Main entry point: EAL init, config loading, main loop, dispatching to node logic
│   ├── dpdk_utils.c       # DPDK helper functions (EAL init, mempool create, port init, rx/tx burst)
│   ├── packet_utils.c     # Packet parsing (Eth, IP, SRH), header manipulation helpers
│   ├── pot/               # Proof of Transit core logic module
│   │   ├── pot_profile.c  # Loading/managing POT profile data (prime, shares, LPCs, validator key etc.)
│   │   ├── pot_core.c     # Core POT calculations (poly eval, CML update, verification logic based on SSS)
│   │   ├── pot_tlv.c      # Reading/writing POT data (RND, CML, profile index flag) from/to packets (e.g., SRH TLV or custom header)
│   │   └── opot.c         # Optional: Ordered POT masking logic (XORing with upstream/downstream masks)
│   ├── crypto_utils.c     # Cryptographic functions (HMAC calculation/verification, potentially optimized XOR for OPOT)
│   ├── node_logic/        # Specific logic executed based on the node's configured role
│   │   ├── ingress_node.c # Implements Ingress logic: generate RND, init CML, add POT data, first POT step, potentially OPOT downstream mask XOR
│   │   ├── transit_node.c # Implements Transit logic: POT CML update step, potentially OPOT upstream/downstream mask XOR
│   │   └── verifier_node.c# Implements Verifier logic: Final POT CML update step, verification (CML vs SECRET+RND), potentially OPOT upstream mask XOR
│   └── config_loader.c    # Optional: Loading runtime config (node role, profiles) from files (e.g., JSON)
└── scripts/               # Utility scripts
    ├── setup_env.sh       # Environment setup (DPDK bindings, hugepages - replaces commands.txt)
    ├── start.sh           # Start script (handles args, selecting node role based on config)
    ├── stop.sh            # Stop script (e.g., kill process)
    └── show_stats.sh      # Example: Script to query DPDK port stats
