#include "utils/utils.h"

void parse_args(int argc, char *argv[]) {
  // Get index where application arguments start, this is indicated with
  // "--" in the command line, after the double dash the arguments are
  // considered application specific and not related to the DPDK framework,
  // such as EAL.
  int app_arg_start = 1;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      app_arg_start = i + 1;
      break;
    }
  }

  // After the above loop, we can pivot from the EAL arguments to the
  // application arguments. The arguments provided also sets up
  // environment variables as well.
  for (int i = app_arg_start; i < argc; i++) {
    // From here on the argument parsing is just a string compare
    // and bunch of switch cases, depending on the received argument,
    // related functions are called
    switch (argv[i][0]) {
      // Argument that sets up the role of the current running instance of the
      // DPDK application, it affects how the packets are processed and send
      // it is crucial part of the application logic.
      case '--role':
      case '-r': {
        // Feed the related function for this arugment with the value of this
        // argument which just i+1
      }

      // Argument that sets up the log level, it is broadcasted to all
      // RTE_LOG definitions, it is utilized under the central logging
      // definition under `logging.c` file
      case '--log-level':
      case '-l': {
      }

      // --segment-list: Optional argument to specify a custom segment list
      // If not provided, the application uses a predefined segment list hardcoded in the code.
      // These segments are defined in the packet header's SRH (Segment Routing Header) section.
      // The packet processing logic varies based on the "segments left" value in the SRH,
      // making this configuration critical to the application's routing behavior.
      case '--segment-list':
      case '-sl': {
      }
    }
  }