#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "utils/config.h"
#include "utils/logging.h"

int read_segment_list(const char *file_path) {
  FILE *f = fopen(file_path, "r");
  if (!f) {
    perror("Failed to open segment list file");
    return -1;
  }

  //TODO implement the logic of reading the segment list from a file and returning 
  // it in the desired format.
  // ...

}