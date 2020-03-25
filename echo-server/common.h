#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>

void hijack_start(void *target, void *new);
// void hijack_pause(void *target);
// void hijack_resume(void *target);
void hijack_stop(void *target);

