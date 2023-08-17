// Write a simple stress test program that crashes.
// This is used to test the crash handler.
// Use pthreads to create multiple threads,
// and set random crash signals(e.g. SIGSEGV) to crash the threads.
// Usage: crash_stress_test [test_tiems] [frequency]

#include <pthread.h>
#include <signal.h>

#include <iostream>

using namespace std;

void* thread_func(void* arg) {
  // Do nothing, just print pid and sleep.
  cout << "In thread " << pthread_self() << " is running..." << endl;
  while (true) {
  }
  return NULL;
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    cout << "Usage: " << argv[0] << " [test_times] [frequency]" << endl;
    return 1;
  }
  int test_times = atoi(argv[1]);
  int frequency = atoi(argv[2]);
  cout << "test_times: " << test_times << endl;
  cout << "frequency: " << frequency << endl;
  srand(time(NULL));
  pthread_t* threads = new pthread_t[test_times];

  for (int i = 0; i < test_times; ++i) {
    int res = pthread_create(&threads[i], NULL, thread_func, NULL);
    if(res != 0) {
      cout << "pthread_create failed, id: " << i << endl;
      return 1;
    }
    cout << "thread " << threads[i] << " is running..." << endl;

    sleep(1);
    // pthread_kill(threads[i], SIGSEGV);
    pthread_kill(threads[i], SIGKILL);

    // pthread_join(threads[i], NULL);
  }

  cout << "hi" << endl;

  // for (int i = 0; i < test_times; ++i) {
  //   int r = rand() % frequency;
  //   if (r == 0) {
  //     pthread_kill(threads[i], SIGSEGV);
  //   }
  // }

  // for (int i = 0; i < test_times; ++i) {
  //   pthread_join(threads[i], NULL);
  // }
  delete[] threads;
  return 0;
}