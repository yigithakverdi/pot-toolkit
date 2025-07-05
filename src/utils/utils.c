#include "utils/utils.h"

#include <stdlib.h>

#include "utils/logging.h"
#include "utils/role.h"

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

    // Argument that sets up the role of the current running instance of the
    // DPDK application, it affects how the packets are processed and send
    // it is crucial part of the application logic.
    if (strcmp(argv[i], "--role") == 0 || strcmp(argv[i], "-r") == 0) {
      // Feed the related function for this arugment with the value of this
      // argument which just i+1

      enum role r = setup_node_role(argv[i + 1]);
      printf("[INFO] Node role set to: %s\n", get_role_name(r));
      // Increment i to skip the next argument which is the value of this one
      i++;
    }

    // Argument that sets up the log level, it is broadcasted to all
    // RTE_LOG definitions, it is utilized under the central logging
    // definition under `logging.c` file
    //
    // TODO: Instead of printing the value of the arugments directly taken from
    // `argv` instead use the value returned from the function
    else if (strcmp(argv[i], "--log-level") == 0 || strcmp(argv[i], "-l") == 0) {
      init_logging("/var/log/dpdk-pot", "dpdk-pot", RTE_LOG_DEBUG);
      printf("[INFO] Log level set to: %s\n", argv[i + 1]);

      // Increment i to skip the next argument which is the value of this one
      i++;
    }

    // --segment-list: Optional argument to specify a custom segment list
    // If not provided, the application uses a predefined segment list hardcoded in the code.
    // These segments are defined in the packet header's SRH (Segment Routing Header) section.
    // The packet processing logic varies based on the "segments left" value in the SRH,
    // making this configuration critical to the application's routing behavior.
    //
    // TODO: Instead of printing the value of the arugments directly taken from
    // `argv` instead use the value returned from the function
    else if (strcmp(argv[i], "--segment-list") == 0 || strcmp(argv[i], "-sl") == 0) {
      read_segment_list(argv[i + 1]);
      printf("[INFO] Segment list file set to: %s\n", argv[i + 1]);

      // Increment i to skip the next argument which is the value of this one
      i++;
    }

    // Help argument, it prints out the help message
    else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      printf("Usage: dpdk-pot [options]\n");
      printf("Options:\n");
      printf("  --role, -r <role>          Set the role of the node (client, server, proxy)\n");
      printf("  --log-level, -l <level>  Set the log level (debug, info, warning, error)\n");
      printf("  --segment-list, -sl <file> Specify a custom segment list file\n");
      printf("  --help, -h                Show this help message\n");
      exit(0);
    }

    // Default case, if the argument is not recognized, it prints an error message
    else {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      fprintf(stderr, "Use --help for usage information.\n");
      exit(EXIT_FAILURE);
    }
  }
}