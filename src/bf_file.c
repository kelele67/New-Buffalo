#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "buffalo.h"
#include "bf_file.h"
#include "bf_user.h"
#include "bf_memory.h"
#include "bf_utils.h"

struct file_info *bf_file_get_info(char *path) {
    struct file_info *f_info;
    struct stat f, target;

    /* 获取一些文件的 stat 信息 */
    if (lstat(path, &f) == -1) {
        return NULL;
    }

    f_info = bf_alloc(sizeof(struct file_info));
    f_info->is_link = BF_FILE_FALSE;
    f_info->is_directory = BF_FILE_FALSE;
    f_info->exec_access = BF_FILE_FALSE;
    f_info->read_access = BF_FILE_FALSE;

    /* 是否是一个连接 */
    if (S_ISLNK(f.st_mode)) {
        f_info->is_link = BF_FILE_TRUE;
        if (stat(path, &target) == -1) {
            return NULL;
        }
    } else {
        target = f;
    }

    f_info->size = target.st_size;
    f_info->last_modification = target.st_mtime;

    /* 是否是一个目录 */
    if (S_ISDIR(target.st_mode)) {
        f_info->is_directory = BF_FILE_TRUE;
    }

    /* 检查 read access */
    /* read user, read group, read other*/
    if (((target.st_mode & S_IRUSR) && target.st_uid == EUID) ||
        ((target.st_mode & S_IRGRP) && target.st_gid == EGID) ||
        (target.st_mode & S_IROTH)) {
            f_info->read_access = BF_FILE_TRUE;
        }
#ifdef TRACE
    else {
        BF_TRACE("Target has not read access");
    }
#endif

    /* 检查 execution access */
    if ((target.st_mode & S_IXUSR && target.st_uid == EUID) ||
        (target.st_mode & S_IXGRP && target.st_gid == EGID) ||
        (target.st_mode & S_IXOTH)) {
            f_info->exec_access = BF_FILE_TRUE;
        }
#ifdef TRACE
    else {
        BF_TRACE("Warning: target has not execution permission");
    }
#endif

    return f_info;
}

/* 读文件到 buffer，
 * 用于小文件
 */
char *bf_file_to_buffer(char *path) {
    FILE *fp; /* 定义一个文件指针 */
    char *buffer;
    long bytes;
    struct file_info *finfo;

    if (!(finfo = bf_file_get_info(path))) {
        return NULL;
    }

    if (!(fp = fopen(path, "r"))) {
        return NULL;
    }

    buffer = calloc(finfo->size + 1, sizeof(char));
    if (!buffer) {
        fclose(fp);
        return NULL;
    }

    bytes = fread(buffer, finfo->size, 1, fp);

    if (bytes < 1) {
        bf_free(buffer);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    return (char *) buffer;
}