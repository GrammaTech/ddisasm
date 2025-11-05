// Initialized thread-local object (.tdata):
__thread int initialized1 = 4;

// Uninitialized thread-local object (.tbss):
__thread int uninitialized1;

__thread long initialized2 = 10;

__thread int uninitialized2;
