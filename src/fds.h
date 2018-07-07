#ifndef FDS_H
#define FDS_H

int setup_fd();
int is_valid_fd(int fd);
int closefrom(int minfd);

#endif
