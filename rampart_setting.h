#ifndef RAMPART_SETTING_H
#define RAMPART_SETTING_H

#define ALPHA 1.0 /* Paramter used for calculating termination probability */
#define CPU_USAGE_LOWER_THRESHOLD 25 /* */
#define CPU_USAGE_UPPER_THRESHOLD 50 /* Threshold to control whether we should allow a TP/FP to execute */
#define ENABLE_RULE 1 /* Build filtering rules of aborted requests */
#define FORCE_TERMINATION 0 /* Force termination if greater than 0 */
#define MAX_PROF_DEPTH 5 /* Max number of profiled entries (excluding ROOT_SYMBOL) in the stack  */
#define OMEGA 1.0 /* Paramter used for calculating termination probability */
#define PROF_RATIO 1 /* only 1/PROF_RATIO function calls are fully profiled */
#define SLEEP_TIME 5 /* Sleep the process for SLEEP_TIME milli seconds if it should not be terminated */
#define TRAINING 0 /* Enables training-only mode if positive */

#endif /* RAMPART_SETTING_H */
