#ifndef __NJK_PIDFILE_H_
#define __NJK_PIDFILE_H_ 1
void write_pid(char *file);
void fail_on_fdne(char *file, char *mode);
#endif

