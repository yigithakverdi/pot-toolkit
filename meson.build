project('dpdk-pot', 'c') 

dep_dpdk = dependency('libdpdk', 
  fallback: ['dpdk', 'dpdk_dep'],
  default_options: ['default_library=static']
)

openssl_dep = dependency('openssl',
  fallback: ['openssl', 'openssl_dep'],
  required: true
)

inc = include_directories('include')

# Grab C files from project root
root_src = files('main.c')

# Run the script to grab .c files under src/
grabber = run_command('./scripts/grabber.sh', check: true)
src_files = grabber.stdout().strip().split('\n')

all_sources = root_src + src_files

executable('dpdk-pot', 
  all_sources, 
  dependencies : [dep_dpdk, openssl_dep],
  include_directories : inc
)