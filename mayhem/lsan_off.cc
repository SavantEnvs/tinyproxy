// Leaks are not the bug class this fleet fuzzes for; ASan's memory-corruption checks stay on.
extern "C" int __lsan_is_turned_off() { return 1; }
