#ifndef BF_FILE_H
#define BF_FILE_H

#define BF_FILE_TRUE 1
#define BF_FILE_FALSE 0

struct file_info{
    off_t size;
    short int is_link;
    short int is_directory;
    short int exec_access;
    short int read_access;
    time_t last_modification;
};

struct file_info *bf_file_get_info(char *path);
char *bf_file_to_buffer(char *path);

#endif