/*
 * The Crab Trap - BroncoCTF 2026
 * Category: pwn
 *
 * "Welcome to Mr. Krabs' secret vault. But beware — the barnacles
 *  are watching every syscall you make..."
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <unistd.h>

/* ─── ASCII Art ─────────────────────────────────────────────────────────── */
void print_banner(void) {
    puts(
        "\n"
        "   /\\_/\\   /\\_/\\\n"
        " =( ^.^ )=( ^.^ )=\n"
        "  | (\") |  | (\") |\n"
        "   \\___/    \\___/\n"
        "  ~~ THE CRAB TRAP ~~\n"
        "\n"
        " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        "  Welcome to Mr. Krabs' Shellcode Emporium!\n"
        "  \"I like money... and restricted syscalls.\"\n"
        "\n"
        "  *** STRICT SEA POLICY IN EFFECT ***\n"
        "  Allowed syscalls: open, read, write\n"
        "  execve?  The barnacles will DESTROY you.\n"
        " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
    );
}

/* ─── Seccomp Filter ─────────────────────────────────────────────────────── */
void apply_barnacle_barrier(void) {
    scmp_filter_ctx ctx;

    /* Default action: SCMP_ACT_KILL — any unlisted syscall kills the process */
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        perror("seccomp_init");
        exit(1);
    }

    /* execve / execveat are NOT on the allowlist below, so they are killed by
     * the default SCMP_ACT_KILL policy — no explicit rule needed. */

    /* ── Allowlist: only the small fish get through the net ── */
    int allowed[] = {
        SCMP_SYS(rt_sigreturn),
        SCMP_SYS(exit),
        SCMP_SYS(exit_group),
        SCMP_SYS(read),
        SCMP_SYS(write),
        SCMP_SYS(open),
    };

    for (int i = 0; i < (int)(sizeof(allowed) / sizeof(allowed[0])); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed[i], 0) < 0) {
            perror("seccomp_rule_add (allow)");
            seccomp_release(ctx);
            exit(1);
        }
    }

    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(1);
    }

    seccomp_release(ctx);
}

/* ─── Main ───────────────────────────────────────────────────────────────── */
int main(void) {
    /* Disable buffering so the challenge works cleanly over a network socket */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    print_banner();

    /* ── Allocate a RWX page to hold the shellcode ── */
    void *shellcode_buf = mmap(
        NULL,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1, 0
    );
    if (shellcode_buf == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    /* ── Prompt for shellcode ("crab feed") ── */
    printf("\n[*] Drop your crab feed into the trap (max 512 bytes):\n> ");
    fflush(stdout);

    ssize_t n = read(STDIN_FILENO, shellcode_buf, 512);
    if (n <= 0) {
        puts("[-] No feed? Leaving...");
        exit(1);
    }
    printf("[*] Nom nom... swallowed %zd bytes. Deploying the Barnacle Barrier...\n", n);

    /* ── Apply the seccomp filter RIGHT before jumping to shellcode ── */
    apply_barnacle_barrier();

    printf("[*] The trap is set. Good luck, sailor.\n\n");

    /* ── Cast and call — execution handed to the player ── */
    void (*shellcode_fn)(void) = (void (*)(void))shellcode_buf;
    shellcode_fn();

    /* Should never reach here */
    puts("[!] You escaped the trap? Impossible!");
    return 0;
}
