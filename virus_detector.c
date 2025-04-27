#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define VIRUS_NAME_MAX_LEN 16
#define MAGIC_NUMBER_SIZE_IN_BYTES 4
#define USER_INPUT_MAX_LEN 128
#define CHAR_TO_DIGIT_OFFSET 48
#define MAX_FILE_LEN_TO_DETECT_BYTES 10000

char magic_number[MAGIC_NUMBER_SIZE_IN_BYTES]; // Global var to check byte swapping

// Helper func to swap bytes in a short (virus sig len)
unsigned short swapBytes(unsigned short value) {
    return (value >> 8) | (value << 8);
}

typedef struct virus {
    unsigned short SigSize;
    char virusName[VIRUS_NAME_MAX_LEN];
    unsigned char* sig;
} virus; 

typedef struct link link; 
struct link {
    link *nextVirus;
    virus *vir;
};

// Function that reads a virus from the signatures file
virus* readVirus(FILE* file){
    // Allocating virus memory
    virus* v = (virus*)malloc(sizeof(virus)); 

    if(fread(v, sizeof(unsigned short) + sizeof(unsigned char)*VIRUS_NAME_MAX_LEN, 1, file) <= 0) {
        // Free the virus and return NULL (for end of file purposes)
        free(v);
        return NULL;
    };
    
    if (strcmp(magic_number, "VIRB") == 0) v->SigSize = swapBytes(v->SigSize); // Manipulate bytes if big-endian

    // Allocating and reading the virus signature
    v->sig = (unsigned char*)malloc(v->SigSize);
    fread(v->sig, sizeof(unsigned char), v->SigSize, file);
    return v;
}

// Fuction that prints a virus struct
void printVirus(virus* virus, FILE* output){
    int i;
    if(output){
        fprintf(output, "Virus name: %s\nVirus size: %d\nsignature:\n", virus->virusName, virus->SigSize);
        for(i = 0; i < virus->SigSize; i++){
            fprintf(output, "%x ", virus->sig[i]);
        }
        fprintf(output, "\n\n");  
    }
}

// Function that prints a virus linked-list
void list_print(link* virus_list, FILE* output){
    while(virus_list->nextVirus != NULL){
        printVirus(virus_list->vir, output);
        virus_list = virus_list->nextVirus;
    }
    printVirus(virus_list->vir, output);
}

// Function that appends a new link to the linked-list
link* list_append(link* virus_list, virus* data){
    link* runner;
    link* new_link;

    // Check if it is an empty linked-list
    if(virus_list->vir == NULL){
        virus_list->vir = data;
        return virus_list;
    }

    // Not an empty list
    runner = virus_list;
    new_link = (link*)malloc(sizeof(link));
    new_link->vir = data;
    while(runner->nextVirus != NULL){
        runner = runner->nextVirus;
    }   
    runner->nextVirus = new_link;
    return virus_list;
}

// Free a given linked-list, also freeing the virus struct that inside the link
void list_free(link* virus_list){
    while(virus_list->nextVirus != NULL){
        link* next_link = virus_list->nextVirus;
        free(virus_list->vir->sig);
        free(virus_list->vir);
        free(virus_list);
        virus_list = next_link;
    }
    free(virus_list->vir->sig);
    free(virus_list->vir);
    free(virus_list);
}

// Loading a signature file into a linked list.
link* load_sig(){
    char filename[USER_INPUT_MAX_LEN];
    FILE* bin_file;

    link* virus_list;
    virus* curr_virus;
    int i;

    // Accepting filename input, assuming not larger than USER_INPUT_MAX_LEN
    printf("Enter a signature file name: ");
    fgets(filename, USER_INPUT_MAX_LEN, stdin);
    i = 0;
    while(filename[i] != '\n'){
        i++;
    }
    filename[i] = '\0';
    bin_file = fopen(filename, "rb");

    if (bin_file == NULL){
        fprintf(stderr, "Error in opening file: %s.\n", filename);
        return NULL;
    }

    // Read the magic number
    fread(magic_number, sizeof(unsigned char), MAGIC_NUMBER_SIZE_IN_BYTES, bin_file);
    magic_number[4] = '\0'; // Ensure null-terminated
    if(strcmp(magic_number, "VIRL") != 0 && strcmp(magic_number, "VIRB") != 0){
        fprintf(stderr, "Error magic number is wrong, expected VIRB or VIRL, got %s\n", magic_number);
        return NULL;
    }

    // Building the linked-list
    virus_list = (link*)malloc(sizeof(link));
    while((curr_virus = readVirus(bin_file)) != NULL){
        list_append(virus_list, curr_virus);
    }

    // Close the file
    fclose(bin_file);
    return virus_list;
};

void print_sig(link* virus_list){
    if(virus_list != NULL){
        list_print(virus_list, stdout);
    }
};

void detect_viruses(char* buffer, unsigned int size, link* virus_list){

    char filename[USER_INPUT_MAX_LEN];
    FILE* suspected_bin_file;
    int i;
    link* runner = virus_list;

    // Open the suspected file and read it to buffer
    printf("Enter a suspected file name: ");
    fgets(filename, USER_INPUT_MAX_LEN, stdin);
    i = 0;
    while(filename[i] != '\n'){
        i++;
    }
    filename[i] = '\0';
    suspected_bin_file = fopen(filename, "rb");

    if (suspected_bin_file == NULL){
        fprintf(stderr, "Error in opening file: %s.\n", filename);
        return;
    }
    size_t bytes_read;
    bytes_read = fread(buffer, sizeof(char), size, suspected_bin_file);
    fclose(suspected_bin_file);

    while (1){

        i = 0;
        while(i < bytes_read){
            if(memcmp(&buffer[i], runner->vir->sig, runner->vir->SigSize) == 0) {
                printf("Virus found!\nStarting byte location in the suspected file: %d\nThe virus name: %s\nThe size of the virus signature: %d\n", i, runner->vir->virusName, runner->vir->SigSize);
            }
            i++;
        }
        if (runner->nextVirus)
            runner = runner->nextVirus;
        else break;
    }
}

void neutralize_virus(char *fileName, int signatureOffset){
    unsigned char nearRET = 0xC3;

    // Open the file
    FILE* suspected_bin_file = fopen(fileName, "r+b");
    if (suspected_bin_file == NULL){
        fprintf(stderr, "Error in opening file: %s.\n", fileName);
        return;
    }

    // Seek to the virus offset
    if (fseek(suspected_bin_file, signatureOffset, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking position");
        fclose(suspected_bin_file);
        return;
    }

    // Write RET to the position
    if (fwrite(&nearRET, sizeof(unsigned char), 1, suspected_bin_file) != 1) {
        perror("Error writing to file");
        fclose(suspected_bin_file);
        return;
    }

    // Close the file
    fclose(suspected_bin_file);
}

void fix_file(char* buffer, unsigned int size, link* virus_list){
    char filename[USER_INPUT_MAX_LEN];
    FILE* suspected_bin_file;
    int i;
    link* runner = virus_list;

    // Open the suspected file and read it to buffer
    printf("Enter a suspected file name: ");
    fgets(filename, USER_INPUT_MAX_LEN, stdin);
    i = 0;
    while(filename[i] != '\n'){
        i++;
    }
    filename[i] = '\0'; // Ensure null-termination

    // Open the suspected file and check for errors
    suspected_bin_file = fopen(filename, "rb");
    if (suspected_bin_file == NULL){
        fprintf(stderr, "Error in opening file: %s.\n", filename);
        return;
    }
    
    // Read bytes - assuming not larger file than _size_ bytes
    size_t bytes_read;
    bytes_read = fread(buffer, sizeof(char), size, suspected_bin_file);
    fclose(suspected_bin_file);

    while (1){ // Until the linked list ends
        i = 0;
        while(i < bytes_read){ // Looping the buffer
            if(memcmp(&buffer[i], runner->vir->sig, runner->vir->SigSize) == 0) { // Searching for virus sigs
                neutralize_virus(filename, i);
            }
            i++;
        }

        // 
        if (runner->nextVirus)
            runner = runner->nextVirus;
        else break;
    }
}


// Function to gracfully quit the program
void quit(link* virus_list){
    if(virus_list) // Is not null
        list_free(virus_list);
}


// Menu options
char* menu[] = {"Load signatures", "Print signatures", "Detect viruses", "Fix file", "Quit", NULL}; 

int main(int argc, char** argv){
    link* virus_list = NULL;   
    int i;
    char buffer[USER_INPUT_MAX_LEN];
    char menu_action;
    char end_flag = 1;
    char detect_virus_buffer[MAX_FILE_LEN_TO_DETECT_BYTES];

    // Check that there are no args.
    
    if (argc != 1){
        fprintf(stderr, "This program accepts no args.\n");
        return 1;
    }

    
    while(end_flag){ // Menu is still up

        // Print the menu
        printf("Choose an item from the next menu:\n");
        i = 0;
        while(menu[i] != NULL){
            printf("    %d) %s\n", i+1, menu[i]);
            i++;
        }

        fgets(buffer, USER_INPUT_MAX_LEN, stdin); // Assuming input not larger than USER_INPUT_MAX_LEN

        // Exctracting the input, and switch-case the menu
        if (buffer[1] == '\n' && buffer[2] == '\0'){
            menu_action = (int)buffer[0] - CHAR_TO_DIGIT_OFFSET;
            switch(menu_action){
                case 1:{
                    virus_list = load_sig();
                    break;
                }
                case 2:{
                    print_sig(virus_list);
                    break;
                }
                case 3:{
                    detect_viruses(detect_virus_buffer, MAX_FILE_LEN_TO_DETECT_BYTES, virus_list);
                    break;
                }
                case 4:{
                    fix_file(detect_virus_buffer, MAX_FILE_LEN_TO_DETECT_BYTES, virus_list);
                    break;
                }
                case 5:{
                    quit(virus_list);
                    end_flag = 0;
                    break;
                }
                default:{
                    fprintf(stderr, "Error input accepts only digits between 1-5, instead got: %c\n", buffer[0]);
                    break;
                }
            }
        }
        else{
            fprintf(stderr, "Error input accepts only one char. instead got: %s \n", buffer);
        }
    }
    return 0;
}