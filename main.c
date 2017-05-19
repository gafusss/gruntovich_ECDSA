#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <signal.h>

char * privfile = "privkey.pem";
char * pubfile = "pubkey.pem";
char * gen = "gen";
char * a = "a";
char * b = "b";
char * port = "53125";
char * timeout = "0";
char * ip = "127.0.0.1";
char * single = "1";

int main(int argc, char *argv[], char *envp[])
{
    pid_t pid = fork();
    if (pid == -1)
    {
        fprintf(stderr, "Could not fork\n");
        return -1;
    }
    else if (pid == 0)
    {
        //child
        char *args [] = 
        {
            gen,
            privfile,
            pubfile,
            NULL
        };
        if (execve(gen, args, envp) == -1) {
            fprintf(stderr, "Could not execute gen\n");
            return -2;
        }
    }
    else
    {
        int status;
        wait(&status);
        if ((WIFEXITED(status) == 0) || (WEXITSTATUS(status) != 0))
        {
            fprintf(stderr, "Gen failed\n");
            return -3;
        }

        pid_t bpid = fork();
        if (bpid == -1)
        {
            fprintf(stderr, "Could not fork\n");
            return -4;
        }
        else if (bpid == 0)
        {
            //child
            char *args [] = 
            {
                b,
                pubfile,
                port,
                timeout,
                single,
                NULL
            };
            if (execve(b, args, envp) == -1) {
                fprintf(stderr, "Could not execute B\n");
                return -5;
            }
        }
        else
        {
            //B is running with bpid
            sleep(1);
            
            pid_t apid = fork();
            if (apid == -1)
            {
                fprintf(stderr, "Could not fork\n");
                return -6;
            }
            else if (apid == 0)
            {
                //child
                char *args [] = 
                {
                    a,
                    privfile,
                    ip,
                    port,
                    NULL
                };
                if (execve(a, args, envp) == -1) {
                    fprintf(stderr, "Could not execute A\n");
                    return -7;
                }
            }
            else
            {
                int status_a;
                int status_b;
                wait(&status_a);
                if ((WIFEXITED(status_a) == 0) || (WEXITSTATUS(status_a) != 0))
                {
                    fprintf(stderr, "A failed\n");
                    return -8;
                }
                wait(&status_b);
                if ((WIFEXITED(status_b) == 0) || (WEXITSTATUS(status_b) != 0))
                {
                    fprintf(stderr, "B failed\n");
                    return -9;
                }
            }
        }
    }

    return 0;
}