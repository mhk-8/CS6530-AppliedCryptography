# main.py
# Import the main functions from your cipher implementation files

from CS25M028_Salsa20 import run_salsa20_assignment
from CS25M028_ChaCha20 import run_chacha20_assignment

if __name__ == "__main__":
    MY_ROLL_NO = "CS25M028" 
    
    # This is the master switch to enable/disable detailed logs for the core state 
    # Set to True to get the detailed matrix outputs for diffusion analysis (Part 1).
    # Set to False to get clean time measurements for performance analysis (Part 3).
    LOG_CORE_STATE = True
    
    print("=========================================================")
    print("  CS6530 Applied Cryptography - Assignment 1 Execution")
    print(f"  Roll Number: {MY_ROLL_NO}")
    print(f"  Detailed Logging: {'ON' if LOG_CORE_STATE else 'OFF'}")
    print("=========================================================\n")

    # Run the entire assignment for Salsa20
    run_salsa20_assignment(MY_ROLL_NO, log_switch=LOG_CORE_STATE)
    
    # Run the entire assignment for ChaCha20
    run_chacha20_assignment(MY_ROLL_NO, log_switch=LOG_CORE_STATE)

    print("Assignment script finished and all output files have been generated.")
    
    # If you want to run a separate performance-only test with logs off:
    if LOG_CORE_STATE:
        print("\n=========================================================")
        print(" Running a second pass with LOGS OFF for performance analysis.")
        print("=========================================================\n")
        run_salsa20_assignment(MY_ROLL_NO, log_switch=False)
        run_chacha20_assignment(MY_ROLL_NO, log_switch=False)