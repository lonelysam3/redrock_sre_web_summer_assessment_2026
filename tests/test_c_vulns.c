/**
 * C 语言漏洞测试用例
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ======== 命令注入 ========
void vulnerable_ping(int argc, char *argv[]) {
    char cmd[256];
    // 用户输入的 argv[1] 直接拼接到命令中
    sprintf(cmd, "ping -c 1 %s", argv[1]);   // ← SOURCE: argv[1]
    system(cmd);                              // ← SINK: 命令注入
}

void vulnerable_shell() {
    char input[128];
    scanf("%s", input);                       // ← SOURCE: scanf
    system(input);                            // ← SINK: 命令注入
}

// ======== 路径穿越 ========
void vulnerable_file_read(char *filename) {
    // 参数来自用户输入
    FILE *fp = fopen(filename, "r");          // ← SINK: 路径穿越
    if (fp) {
        char buf[256];
        fread(buf, 1, 256, fp);
        fclose(fp);
    }
}

void vuln_with_user_input() {
    char path[256];
    printf("Enter filename: ");
    scanf("%s", path);                        // ← SOURCE: scanf
    FILE *fp = fopen(path, "r");              // ← SINK: 路径穿越
    if (fp) fclose(fp);
}

// ======== 安全的代码 ========
void safe_filename() {
    // 硬编码路径，不来自用户输入
    FILE *fp = fopen("/etc/hosts.allow", "r");  // ← 安全（硬编码）
    if (fp) fclose(fp);
}

void safe_system() {
    // 固定命令，无用户输入
    system("date");                           // ← 安全（无变量拼接）
}

// ======== main ========
int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_ping(argc, argv);
    }
    vulnerable_shell();
    vuln_with_user_input();
    vulnerable_file_read(argv[1]);            // ← SOURCE: argv[1]
    safe_filename();
    safe_system();
    return 0;
}
