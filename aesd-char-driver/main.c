/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h> // krealloc
#include "aesdchar.h"
#include "aesd_ioctl.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

loff_t offset_backup = 0;
 uint8_t ioctl_called = 0;

MODULE_AUTHOR("Eduard Polyakov");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    
    if (ioctl_called) {
        ioctl_called = 0;
        filp->f_pos = offset_backup;
    }

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */

    filp->private_data = NULL;
    
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t entry_offset = 0;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */

    // Acquire mutex for thread safety
    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    // Find the entry and offset corresponding to f_pos
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_offset);

    if (entry) {
        // Calculate how many bytes we can read
        size_t bytes_to_read = entry->size - entry_offset;
        if (bytes_to_read > count)
            bytes_to_read = count;

        // Copy data to user space
        if (copy_to_user(buf, entry->buffptr + entry_offset, bytes_to_read)) {
            retval = -EFAULT;
        } else {
            *f_pos += bytes_to_read;
            retval = bytes_to_read;
        }
    }
    
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;
    char *k_buf, *new_line_pos;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */

    // Allocate temporary kernel buffer
    k_buf = kmalloc(count, GFP_KERNEL);
    if (!k_buf) {
        return -ENOMEM;
    }
    // Copy data from user space
    if (copy_from_user(k_buf, buf, count)) {
        kfree(k_buf);
        return -EFAULT;
    }

    // Find new line
    new_line_pos = memchr(k_buf, '\n', count) != NULL;

    // Acquire mutex
    if (mutex_lock_interruptible(&dev->lock)) {
        kfree(k_buf);
        return -ERESTARTSYS;
    }

    // Check if we need to append to existing entry or create new one
    if (dev->incomplete_entry.buffptr) {
        // Reallocate to accommodate new data
        char *new_buf = krealloc(dev->incomplete_entry.buffptr, 
                               dev->incomplete_entry.size + count, 
                               GFP_KERNEL);
        if (!new_buf) {
            kfree(k_buf);
            mutex_unlock(&dev->lock);
            return -ENOMEM;
        }
        dev->incomplete_entry.buffptr = new_buf;
        memcpy((char *)dev->incomplete_entry.buffptr + dev->incomplete_entry.size,
               k_buf, count);
        dev->incomplete_entry.size += count;
        kfree(k_buf);
    } else {
        dev->incomplete_entry.buffptr = k_buf;
        dev->incomplete_entry.size = count;
    }

    if (new_line_pos != NULL) {
        if (dev->buffer.full) {
            // Save the entry that might be overwritten if buffer is full
            char *buffptr_to_free = (char *)dev->buffer.entry[dev->buffer.out_offs].buffptr;
            aesd_circular_buffer_add_entry(&dev->buffer, &dev->incomplete_entry);
            if (buffptr_to_free) {
                kfree(buffptr_to_free);
            }
        } else {
            // Buffer not full, just add the entry
            aesd_circular_buffer_add_entry(&dev->buffer, &dev->incomplete_entry);
        }
        *f_pos += dev->incomplete_entry.size;   // update f_pos

        // Reset incomplete entry
        dev->incomplete_entry.buffptr = NULL;
        dev->incomplete_entry.size = 0;
    }

    retval = count; 
    mutex_unlock(&dev->lock);
    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t f_offs, int whence) {
    struct aesd_dev *dev = filp->private_data;
    loff_t retval;
    loff_t total_size = 0;
    uint8_t index;

    if (mutex_lock_interruptible(&(dev->lock))) {
        PDEBUG("ERROR: Couldn't acquire lock\n");
        return -ERESTARTSYS;
    }

    // Calculate the total size of all commands in the circular buffer
    for (index = 0; index < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; index++) {
        if (dev->buffer.entry[index].buffptr) {
            total_size += dev->buffer.entry[index].size;
        }
    }

    PDEBUG("aesd_llseek: Current position: %lld, Offset: %lld, Whence: %d\n", filp->f_pos, f_offs, whence);

    switch (whence) {
        case SEEK_SET:
            retval = f_offs;
            PDEBUG("aesd_llseek: SEEK_SET, New position: %lld\n", retval);
            break;
        case SEEK_CUR:
            retval = filp->f_pos + f_offs;
            PDEBUG("aesd_llseek: SEEK_CUR, New position: %lld\n", retval);
            break;
        case SEEK_END:
            retval = total_size + f_offs;
            PDEBUG("aesd_llseek: SEEK_END, New position: %lld\n", retval);
            break;
        default:
            PDEBUG("aesd_llseek: Invalid whence value: %d\n", whence);
            retval = -EINVAL;
            goto out;
    }

    // Check if the new file position is within the range of the circular buffer
    if (retval < 0 || retval > total_size) {
        PDEBUG("aesd_llseek: New position out of range: %lld\n", retval);
        retval = -EINVAL;
        goto out;
    }

    filp->f_pos = retval;

out:
    mutex_unlock(&(dev->lock));
    return retval;
}

static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd,
                                    unsigned int write_cmd_offset) {
    struct aesd_dev *dev = filp->private_data;
    struct aesd_circular_buffer *buffer = &(dev->buffer);
    uint8_t index;
    long retval;
    long new_offset = 0;

    if (mutex_lock_interruptible(&(dev->lock))) {
        return -ERESTARTSYS;
    }

    /* Validate arguments */
    if ((write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) ||
        (buffer->entry[write_cmd].buffptr == NULL) ||
        (buffer->entry[write_cmd].size <= write_cmd_offset)) {
        retval = -EINVAL;
        PDEBUG("Error: invalid argument\n");
        goto inCaseOfFailure;
    }

    /* Set the offset to the demanded offset */

    /* Seek to the start of write_cmd entry */
    for (index = 0; index < write_cmd; index++) {
        new_offset += buffer->entry[index].size;
    }

    /* Add offset */
    new_offset += write_cmd_offset;
    filp->f_pos = new_offset;
    offset_backup = filp->f_pos;
    ioctl_called = 1;
    retval = 0;
    mutex_unlock(&(dev->lock));

    PDEBUG("Your new f_pos is: %lld", filp->f_pos);
inCaseOfFailure:
    return retval;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    long retval;
    struct aesd_seekto seekto;
    PDEBUG("********************************************\n");
    PDEBUG("ioctl is called with command %u\n", cmd);
    switch (cmd) {
    case AESDCHAR_IOCSEEKTO:
        if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto))) {
            PDEBUG("ioctl: Error copying data from user\n");
            retval = -EFAULT;
        } else {
            PDEBUG("ioctl: Adjusting file offset to %u, %u\n", seekto.write_cmd,
                   seekto.write_cmd_offset);
            retval = aesd_adjust_file_offset(filp, seekto.write_cmd,
                                             seekto.write_cmd_offset);
        }
        break;
    default:
        PDEBUG("ioctl: Wrong command\n");
        retval = -EINVAL;
    }
    PDEBUG("********************************************\n");
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek = aesd_llseek,
    .unlocked_ioctl = aesd_ioctl
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */

    // Initialize the mutex for thread safety
    mutex_init(&aesd_device.lock);

    // Circular buffer init (TODO: initialise mutex before)
    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    uint8_t index = 0;
    struct aesd_buffer_entry *entry;
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    // Release the memory
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
        if (entry->buffptr) {
            kfree(entry->buffptr);
        }
    }

     // Destroy the mutex
     mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
