/* 单独编 mesh 时的入口; 并进 custhub 时由 src/client/main.c 调 cmd_mesh */
#include "mesh.h"

int main(int argc, char **argv) { rel_set_args(argv); return cmd_mesh(argc, argv); }
