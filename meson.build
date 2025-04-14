# Global build configurations
project('dpdk-pot', 'c') 

# Meson configuration (meson.build)
dep_dpdk = dependency('libdpdk', 
  fallback: ['dpdk', 'dpdk_dep'],
  default_options: ['default_library=static']
)


# Compiler flags
executable('dpdk-pot', 'main.c', dependencies : [dep_dpdk])