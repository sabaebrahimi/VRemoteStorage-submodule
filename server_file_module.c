#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/mm.h>

#define SERVER_PORT 1104
#define BUFFER_SIZE 1024
#define RESPONSE_MESSAGE "Saba Saba"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Saba Ebrahimi");
MODULE_DESCRIPTION("A simple UDP server kernel module with response");
MODULE_VERSION("1.0");

static struct socket *udp_socket = NULL;      // Socket for the UDP server
static struct task_struct *udp_thread = NULL; // Kernel thread for listening

// Read file
static ssize_t read_file_from_kernel(const char *path, loff_t start, size_t size, char *buffer)
{
    struct file *filp;
    ssize_t bytes_read = 0;

    pr_info("the path is: %s, start is: %llu, size is: %ld\n", path, start, size);

    // Open the file
    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp))
    {
        pr_err("Failed to open file: %s\n", path);
        return PTR_ERR(filp);
    }

    // Read data from file
    bytes_read = kernel_read(filp, buffer, size, &start);
    if (bytes_read < 0)
    {
        pr_err("Failed to read file: %s\n", path);
    }

    printk(KERN_INFO "Received Data: %s\n", buffer);

    filp_close(filp, NULL);

    return bytes_read;
}

static int read_page_cache(const char *file_path, loff_t pos, size_t size, char *buffer)
{
    struct path path;
    int ret;
    pr_info("before kern_path\n");
    ret = kern_path(file_path, LOOKUP_FOLLOW, &path);
    pr_info("After kern_info\n");
    if (ret)
    {
        pr_err("Failed to resolve path: %d\n", ret);
        goto error;
    }

    struct dentry *dentry = path.dentry;
    struct inode *inode = dentry->d_inode;

    while (size)
    {
        struct folio *folio;
        size_t n;
        pr_info("read mapping folio: \n");
        folio = read_mapping_folio(inode->i_mapping, pos >> PAGE_SHIFT,
                                   NULL);
        if (IS_ERR(folio))
            return PTR_ERR(folio);
        pr_info("After read mapping folio: \n");
        n = memcpy_from_file_folio(buffer, folio, pos, size);
        pr_info("After memcpy from file folio \n");
        folio_put(folio);

        buffer += n;
        pos += n;
        size -= n;
    }

error:
    path_put(&path);
    return ret;
}

// Function to send a response
static int send_response(struct socket *sock, struct sockaddr_in *client_addr, char *message)
{
    struct msghdr msg;
    struct kvec iov;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = client_addr;
    msg.msg_namelen = sizeof(*client_addr);

    iov.iov_base = message;
    iov.iov_len = strlen(message);

    ret = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
    if (ret < 0)
    {
        pr_err("UDP Server: Failed to send response, error %d\n", ret);
    }
    else
    {
        pr_info("UDP Server: Response sent to client\n");
    }

    return ret;
}

// Thread function for receiving UDP messages
static int udp_server_thread(void *data)
{
    struct sockaddr_in client_addr;
    struct msghdr msg;
    struct kvec iov;
    char buffer[BUFFER_SIZE];
    char *received_elements[3];
    int ret;

    received_elements[0] = kmalloc(256, GFP_KERNEL);
    received_elements[1] = kmalloc(64, GFP_KERNEL);
    received_elements[2] = kmalloc(64, GFP_KERNEL);

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    // Bind the socket to the server address
    ret = kernel_bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0)
    {
        pr_err("UDP Server: Failed to bind socket, error %d\n", ret);
        return ret;
    }
    pr_info("UDP Server: Listening on port %d\n", SERVER_PORT);

    while (!kthread_should_stop())
    {
        memset(buffer, 0, BUFFER_SIZE);
        memset(&client_addr, 0, sizeof(client_addr));
        memset(&msg, 0, sizeof(msg));

        iov.iov_base = buffer;
        iov.iov_len = BUFFER_SIZE;

        msg.msg_name = &client_addr;
        msg.msg_namelen = sizeof(client_addr);

        // Receive data
        ret = kernel_recvmsg(udp_socket, &msg, &iov, 1, BUFFER_SIZE, MSG_WAITALL);
        if (ret > 0)
        {
            buffer[ret] = '\0';
            char *buffer_ptr = buffer;
            pr_info("UDP Server: Received message: %s\n", buffer);
            char *token;
            int i = 0;

            token = strsep(&buffer_ptr, ",");
            while (token != NULL && i < 3)
            {
                received_elements[i++] = token; // Store token in the array
                token = strsep(&buffer_ptr, ",");
            }
            size_t size;
            unsigned long index;
            if (received_elements[1] != NULL)
            {
                ret = kstrtol(received_elements[1], 10, &size);
                if (ret != 0)
                {
                    printk(KERN_ERR "Failed to convert %s to unsigned long: error %d\n", received_elements[1], ret);
                    return -EINVAL;
                }
            }

            if (received_elements[2] != NULL)
            {
                ret = kstrtol(received_elements[2], 10, &index);
                if (ret != 0)
                {
                    printk(KERN_ERR "Failed to convert %s to unsigned long: error %d\n", received_elements[2], ret);
                    return -EINVAL;
                }
            }

            char *file_content;
            file_content = kmalloc(size, GFP_KERNEL);
            if (!file_content)
            {
                pr_err("Failed to allocate memory for file file_content\n");
                return -ENOMEM;
            }

            loff_t loff_index = (loff_t)index;
            char *path = "/root/load.sh";
            // path = "/root/";
            // strcat(path, received_elements[0]);
            ssize_t result = read_page_cache(path, loff_index, size, file_content);

            printk(KERN_INFO "page cache read %s \n", file_content);
            if (file_content[0] == '\0')
            {
                pr_info("Entered open file \n");
                result = read_file_from_kernel(path, loff_index, size, file_content);
            }
            if (result >= 0)
            {
                pr_info("Read %zd bytes from file %s\n", result, received_elements[0]);
                // Process buffer as needed
            }
            else
            {
                pr_err("Error reading file: %zd\n", result);
            }

            // Send a response to the client
            send_response(udp_socket, &client_addr, file_content);
            // kfree(buffer);
            kfree(file_content);
            kfree(path);
        }
        else if (ret < 0)
        {
            pr_err("UDP Server: Receive error %d\n", ret);
        }

        msleep(100); // Sleep to prevent busy looping
    }

    return 0;
}

// Module initialization
static int __init udp_server_init(void)
{

    int ret;

    pr_info("UDP Server: Initializing module\n");

    // Create a UDP socket
    ret = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &udp_socket);
    if (ret < 0)
    {
        pr_err("UDP Server: Failed to create socket, error %d\n", ret);
        return ret;
    }

    // Start the server thread
    udp_thread = kthread_run(udp_server_thread, NULL, "udp_server_thread");
    if (IS_ERR(udp_thread))
    {
        pr_err("UDP Server: Failed to create thread\n");
        sock_release(udp_socket);
        return PTR_ERR(udp_thread);
    }
    pr_info("UDP Server: Module loaded\n");
    return 0;
}

// Module cleanup
static void __exit udp_server_exit(void)
{
    if (udp_thread)
    {
        kthread_stop(udp_thread);
        pr_info("UDP Server: Thread stopped\n");
    }

    if (udp_socket)
    {
        sock_release(udp_socket);
        pr_info("UDP Server: Socket released\n");
    }

    pr_info("UDP Server: Module unloaded\n");
}

module_init(udp_server_init);
module_exit(udp_server_exit);
