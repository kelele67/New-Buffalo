#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "buffalo.h"
#include "bf_signals.h"
#include "bf_timer.h"
#include "bf_plugin.h"
#include "bf_debug.h"

/* 当捕获信号量并且准备退出时调用这个函数 ->使其关闭了pid,plugin之后安全退出*/
void bf_signal_exit() {
    /* 忽略信号 来 正确处理清理工作 */
    /* SIG_IGN  忽略信号，SIG_DFL 恢复信号的默认行为 */
    signal(SIGTERM, SIG_IGN); /* 结束进程的信号 =kill */
    signal(SIGINT, SIG_IGN); /* 中断信号 Ctrl + C */
    signal(SIGHUP, SIG_IGN); /* 由一个处于非连接状态的终端发给控制进程，或者控制进程在自身结束时发送给每个前台进程 */
    
    bf_utils_remove_pid();
    bf_plugin_exit_all();
    bf_info("Exiting ... > :(");
    _exit(EXIT_SUCCESS);
}

void bf_signal_thread_sigpipe_safe() {
    sigset_t set, old;

    /* 初始化信号集为空 */
    sigemptyset(&set);
    /* 添加将相应的信号加入到信号集*/
    sigaddset(&set, SIGPIPE); /* 加入 向无读管道写数据时产生的信号 */
    /* 设置信号集屏蔽字,此时set中的信号不会被传递给进程，暂时进入待处理状态 */
    pthread_sigmask(SIG_BLOCK, &set, &old);
}

void bf_signal_handler(int signo, siginfo_t *si, void *context) {
    switch (signo) {
        case SIGTERM:
        case SIGINT:
            bf_signal_exit();
            break;
        case SIGHUP:
            /**TODO
            *应该实现httpd config 重载(而不是用SIGUSR2报告状态)。
            *当守护进程“超负荷”这个信号发出时，应该
            *重新加载其配置文件。
            *例如,Apache发送SIGHUP来重读httpd.conf
            */
            bf_signal_exit();
            break;
        case SIGBUS: /* 指针所对应的地址是有效地址，但总线不能正常使用该指针。通常是未对齐的数据访问所致 */
        case SIGSEGV: /* 意味着指针所对应的地址是无效地址，没有物理内存对应该地址 */
            bf_err("%s (%d), code=%d, addr=%p", sys_siglist[signo], signo, si->si_code, si->si_addr);
            pthread_exit(NULL);
        default:
            /* 让内核处理 */
            kill(getpid(), signo);
    }
}

void bf_signal_init() {
    struct sigaction action;
    memset(&action, 0x0, sizeof(action));

    /* 允许并行处理 signals */
    action.sa_flags = SA_SIGINFO | SA_NODEFER;
    action.sa_sigaction = &bf_signal_handler;

    /* 发出相应的信号，并跳转到信号处理函数处 */
    sigaction(SIGTERM, &action, 0);
    sigaction(SIGINT, &action, 0);
    sigaction(SIGHUP, &action, 0);
    sigaction(SIGBUS, &action, 0);
    sigaction(SIGSEGV, &action, 0);

}