#include <unistd.h>
#include <string.h>

#include "libinetsec.h"

#define USER "cs19m046"
#define PASSWORD "cs19m046"

int auth_user(char *user, char *pass) {
    /**if (strncmp(user, USER, sizeof(USER) - 1))
        return 0;
    if (strncmp(pass, PASSWORD, sizeof(PASSWORD) - 1))
        return 0;**/

    return getuid()+1;
}

void init_canary(byte *canary, char *seed) {
    *canary = seed[0];
}

int check_canary(byte *canary, char *seed) {
    return *canary == *seed;
}

int check_usr(char *user, char *pass) {

    return getuid();

}
