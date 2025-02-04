/*
 * Copyright (c) 2025 Abdul Manan
 * File created: 2025-01-20--16:35:03
 * Last modified: 2025-02-03--19:57:47
 * All rights reserved.
 */


#include "constants.h"
#include "../common/common.h"
#include "fs.h"


// Array to store file metadata.
struct file files[FILES_MAX];

// Simulated disk buffer.
uint8_t disk[DISK_MAX_SIZE];

/*
 * oct2int
 *
 * Converts an octal string to an integer.
 *
 * Input:
 *   oct - Pointer to the octal string.
 *   len - Length of the octal string.
 *
 * Process:
 *   - Iterates through each character in the string.
 *   - Stops processing if a non-octal digit is encountered.
 *   - Converts the octal string to a decimal integer.
 *
 * Output:
 *   Returns the decimal representation of the octal number.
 */
int oct2int(char *oct, int len) {
    int dec = 0;
    for (int i = 0; i < len; i++) {
        if (oct[i] < '0' || oct[i] > '7')
            break;

        dec = dec * 8 + (oct[i] - '0');
    }
    return dec;
}

/*
 * fs_init
 *
 * Initializes the filesystem by loading file metadata from a tar archive.
 *
 * Process:
 *   - Reads disk sectors into memory.
 *   - Iterates through the tar archive headers to extract file metadata.
 *   - Validates the tar header format.
 *   - Stores file information in the in-memory `files` array.
 *
 * Output:
 *   The filesystem is initialized and ready for use.
 */
void fs_init(void) {
    for (unsigned sector = 0; sector < sizeof(disk) / SECTOR_SIZE; sector++)
        read_write_disk(&disk[sector * SECTOR_SIZE], sector, false);

    unsigned off = 0;
    for (int i = 0; i < FILES_MAX; i++) {
        struct tar_header *header = (struct tar_header *) &disk[off];

        if (header->name[0] == '\0')
            break;

        if (strcmp(header->magic, "ustar") != 0)
            PANIC("invalid tar header: magic=\"%s\"", header->magic);

        int filesz = oct2int(header->size, sizeof(header->size));

        struct file *file = &files[i];
        file->in_use = true;
        strcpy(file->name, header->name);
        memcpy(file->data, header->data, filesz);
        file->size = filesz;

        printf("file: %s, size=%d\n", file->name, file->size);

        off += align_up(sizeof(struct tar_header) + filesz, SECTOR_SIZE);
    }
}

/*
 * fs_flush
 *
 * Writes the in-memory filesystem state back to disk in tar format.
 *
 * Process:
 *   - Clears the disk buffer.
 *   - Iterates through the `files` array and writes file metadata and data to disk.
 *   - Computes and writes a valid tar header for each file.
 *   - Converts file sizes to octal format.
 *   - Computes and stores checksum values.
 *   - Writes the updated disk buffer to the virtio-blk device.
 *
 * Output:
 *   The filesystem state is persisted to disk.
 */
void fs_flush(void) {
    memset(disk, 0, sizeof(disk));

    unsigned off = 0;
    for (int file_i = 0; file_i < FILES_MAX; file_i++) {
        struct file *file = &files[file_i];

        if (!file->in_use)
            continue;

        struct tar_header *header = (struct tar_header *) &disk[off];
        memset(header, 0, sizeof(*header));

        strcpy(header->name, file->name);
        strcpy(header->mode, "000644"); // Default file permissions.
        strcpy(header->magic, "ustar");
        strcpy(header->version, "00");
        header->type = '0'; // Regular file.

        // Convert file size to octal.
        int filesz = file->size;
        for (int i = sizeof(header->size); i > 0; i--) {
            header->size[i - 1] = (filesz % 8) + '0';
            filesz /= 8;
        }

        // Compute checksum by summing all bytes in the header.
        int checksum = ' ' * sizeof(header->checksum);
        for (unsigned i = 0; i < sizeof(struct tar_header); i++)
            checksum += (unsigned char) disk[off + i];

        // Store checksum as an octal string.
        for (int i = 5; i >= 0; i--) {
            header->checksum[i] = (checksum % 8) + '0';
            checksum /= 8;
        }

        // Copy file data into the disk buffer.
        memcpy(header->data, file->data, file->size);

        off += align_up(sizeof(struct tar_header) + file->size, SECTOR_SIZE);
    }

    // Write updated disk buffer to storage.
    for (unsigned sector = 0; sector < sizeof(disk) / SECTOR_SIZE; sector++)
        read_write_disk(&disk[sector * SECTOR_SIZE], sector, true);

    printf("wrote %d bytes to disk\n", sizeof(disk));
}

/*
 * fs_lookup
 *
 * Searches for a file by name in the in-memory filesystem.
 *
 * Input:
 *   filename - Name of the file to search for.
 *
 * Process:
 *   - Iterates through the `files` array.
 *   - Compares the given filename with stored filenames.
 *
 * Output:
 *   Returns a pointer to the file structure if found, otherwise NULL.
 */
struct file *fs_lookup(const char *filename) {
    for (int i = 0; i < FILES_MAX; i++) {
        struct file *file = &files[i];

        if (!strcmp(file->name, filename))
            return file;
    }

    return NULL;
}
