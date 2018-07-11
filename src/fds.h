#ifndef FDS_H
#define FDS_H

int setup_fd(const struct cjail_para para);
int is_valid_fd(int fd);
int closefrom(int minfd);

#endif
