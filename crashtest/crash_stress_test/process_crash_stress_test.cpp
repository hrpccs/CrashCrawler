// Write a simple stress test program that crashes.
// This is used to test the crash handler.
// Use folk to create multiple process,
// and set random crash signals(e.g. SIGSEGV) to crash the threads.
// Usage: crash_stress_test [test_tiems] [frequency]

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <iostream>

int main(int argc, char* argv[]){
    if(argc < 3){
        std::cout << "Usage: " << argv[0] << " [test_times] [frequency]" << std::endl;
        return 0;
    }
    int test_times = atoi(argv[1]);
    int frequency = atoi(argv[2]);
    for(int i = 0; i < test_times; i++){
        pid_t pid = fork();
        if(pid == 0){
            srand(time(NULL));
            int crash_signal = rand() % 15 + 1;
            std::cout << "Child process " << getpid() << " crashed with signal " << crash_signal << std::endl;
            kill(getpid(), SIGSEGV);
            return 0;
        }
        else{
            int status;
            waitpid(pid, &status, 0);
            if(WIFSIGNALED(status)){
                std::cout << "Child process " << pid << " crashed with signal " << WTERMSIG(status) << std::endl;
            }
            else{
                std::cout << "Child process " << pid << " exited normally" << std::endl;
            }
        }
        // usleep(frequency);
        // sleep(1);
    }
    return 0;
}