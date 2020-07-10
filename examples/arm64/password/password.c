#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFF_LEN 256

typedef struct user_t user_t;

struct user_t
{
    user_t* next;
    char name[BUFF_LEN];
    char password[BUFF_LEN];
    size_t balance;
};

user_t* setup_users()
{
    user_t* user_admin = malloc(sizeof(user_t));
    strcpy(user_admin->name, "admin");
    strcpy(user_admin->password, "4dm1n__4eva");
    user_admin->balance = 1000000;

    user_t* user_alice = malloc(sizeof(user_t));
    strcpy(user_alice->name, "alice");
    strcpy(user_alice->password, "!alice12!_veuje@@hak");
    user_alice->balance = 783;

    user_t* user_abdul = malloc(sizeof(user_t));
    strcpy(user_abdul->name, "abdul");
    strcpy(user_abdul->password, "passw0rd123");
    user_abdul->balance = 2;

    user_admin->next = user_alice;
    user_alice->next = user_abdul;
    user_abdul->next = NULL;

    return user_admin;
}

void print_users(user_t* users)
{
    printf("--- USERS ---\n");
    size_t count = 0;
    while(users != NULL)
    {
        printf(" %02ld. %s\n", ++count, users->name);
        users = users->next;
    }
    printf("\n");
}

user_t* getUser(user_t* user_list, char* name)
{
    while(user_list != NULL)
    {
        if(strcmp(user_list->name, name) == 0)
        {
            return user_list;
        }
        user_list = user_list->next;
    }
    return NULL;
}

int main()
{
    user_t* users = setup_users();

    printf("Welcome to BigBank Australia!\n");

    char username[BUFF_LEN];
    printf("Username: ");
    scanf("%255s", username);

    user_t* user = getUser(users, username);
    if(user == NULL)
    {
        printf("User < %s > does not exist.\n", username);
        return 0;
    }

    char password[BUFF_LEN];
    printf("Password: ");
    scanf("%255s", password);
    if(strcmp(user->password, password) != 0)
    {
        printf("ERROR: incorrect password\n");
        return 0;
    }

    printf("Logged in as < %s >!\n", user->name);
    printf("\n");
    printf("Welcome, %s!\n", user->name);
    printf("Your balance: $%ld\n", user->balance);
}
