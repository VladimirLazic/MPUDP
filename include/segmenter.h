//
// Created by niketic95 on 23/05/17.
//

#ifndef P_SEGMENTER_H
#define P_SEGMENTER_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct segment_s {
    char *data;
    unsigned int segmentNumber;
} Segment;
typedef struct fileinfo_s {
    char *filename;
    unsigned int numberOfSegments;
    unsigned int lengthOfSegment;
    unsigned int lengthOfLastSegment;
} FileInfo;

char *ExtractFilename(const char *path);
// Releases memory for filename string
void EraseFileInfo(FileInfo);
// Frees memory for segments
void EraseSegmentinfo(Segment **, unsigned int);
// Opens file and divides into segments of length N
// 1st arg is the ize of a segment in Bytes
// 2nd arg is a path to the file
// 3rd arg is a Segment pointer in which the file information will be written to
// returns file information (see defines for Fileinfo struct)
FileInfo OpenAndDivide(unsigned int, const char *, Segment **);
// prints the file and its segments
void PrintInfo(FileInfo, Segment *);
// reconstructs the file and its full contents
void Reconstruct(FileInfo, Segment *);
// sorts segments against their segment numbers
void SortSegments(Segment *, FileInfo);
// Clears data of N bytes
void ClearBuffer(char *, unsigned int);
char *ExtractFilename(const char *path) {
    char *temp = NULL;
    int i = 0;
    int j = 0;
    int k = 0;
    while (path[i] != 0) {
        i++;
    }
    j = i - 1;
    while (path[j] != '/' && j >= 0) {
        j--;
    }
    j++;

    temp = (char *)malloc((i - j + 1) * sizeof(char));
    if (temp == NULL) {
        printf("Couldnt allocate memory for storing filename");
        exit(EXIT_FAILURE);
    }
    while (j != i) {
        temp[k] = path[j];
        j++;
        k++;
    }
    return temp;
}
void ClearBuffer(char *data, unsigned int N) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        data[i] = 0;
    }
}
void EraseFileInfo(FileInfo info) { free(info.filename); }
void EraseSegmentinfo(Segment **segmentinfo, unsigned int numberOfSegments) {
    unsigned int i = 0;
    for (i = 0; i < numberOfSegments; i++) {
        free((*segmentinfo)[i].data);
    }
    free(*segmentinfo);
}
FileInfo OpenAndDivide(unsigned int N, const char *file_path,
                       Segment **segment) {

    unsigned int sizeOfFile = 0;
    unsigned int sizeOfSegment = 0;
    char byte = 0;
    unsigned int numberOfSegments = 1;
    char stream[N + 1];
    FILE *source = NULL;
    char *filename = NULL;
    FileInfo ret;

    source = fopen(file_path, "rb");
    if (source == NULL) {
        printf("Cant open %s\n", file_path);
        exit(EXIT_FAILURE);
    }
    rewind(source);
    filename = ExtractFilename(file_path);
    ret.filename = filename;
    ret.lengthOfSegment = N;
    ClearBuffer(stream, N + 1);
    do {
        byte = fgetc(source);
        if (feof(source))
            break;
        sizeOfFile++;
        stream[sizeOfSegment] = byte;

        if (N - 1 - sizeOfSegment == 0) {
            *segment =
                    (Segment *)realloc(*segment, sizeof(Segment) * numberOfSegments);
            if (*segment == NULL) {
                puts("Not enough memory for a segment");
                exit(EXIT_FAILURE);
            }

            (*segment)[numberOfSegments - 1].data =
                    (char *)malloc(ret.lengthOfSegment + 1);

            if ((*segment)[numberOfSegments - 1].data == NULL) {
                puts("Not enough memory for allocating segment data");
                exit(EXIT_FAILURE);
            }

            ClearBuffer((*segment)[numberOfSegments - 1].data, N + 1);
            strcpy((*segment)[numberOfSegments - 1].data, stream);
            (*segment)[numberOfSegments - 1].segmentNumber = numberOfSegments;

            ClearBuffer(stream, N);
            sizeOfSegment = 0;
            numberOfSegments++;
        } else
            sizeOfSegment++;
    } while (1);
    if (sizeOfFile == 0) {
        printf("Empty file or Premature EOF... aborting\n");
        exit(EXIT_FAILURE);
    }
    *segment = (Segment *)realloc(*segment, sizeof(Segment) * numberOfSegments);
    if (*segment == NULL) {
        puts("Not enough memory for allocating a segment");
        exit(EXIT_FAILURE);
    }
    (*segment)[numberOfSegments - 1].data =
            (char *)malloc(ret.lengthOfSegment + 1);
    if ((*segment)[numberOfSegments - 1].data == NULL) {
        puts("Not enough memory for allocating segment data");
        exit(EXIT_FAILURE);
    }
    ClearBuffer((*segment)[numberOfSegments - 1].data, N + 1);
    strcpy((*segment)[numberOfSegments - 1].data, stream);
    (*segment)[numberOfSegments - 1].segmentNumber = numberOfSegments;
    ret.numberOfSegments = numberOfSegments;
    ret.lengthOfLastSegment = sizeOfSegment;
    fclose(source);
    return ret;
}
void PrintInfo(FileInfo info, Segment *segment) {
    printf("\nPRINTING FILE INFORMATION\n\n");
    printf("FILENAME:                     %s\n", info.filename);
    printf("NUMBER OF SEGMENTS            %u\n", info.numberOfSegments);
    printf("LENGTH OF A SEGMENT:          %u\n", info.lengthOfSegment);
    printf("LENGTH OF THE LAST SEGMENT:   %u\n\n", info.lengthOfLastSegment);

    printf("\nPRINTING SEGMENTS INFORMATION\n\n");
    unsigned int i = 0;
    for (i = 0; i < info.numberOfSegments; i++) {
        printf("SEGMENT NUMBER:                     %u\n",
               segment[i].segmentNumber);
        printf("DATA OF SEGMENT:                    %s\n\n", segment[i].data);
    }
}

void Reconstruct(FileInfo info, Segment segment[]) {
    FILE *dest = fopen(info.filename, "wb");
    unsigned int i = 0;
    if (dest == NULL) {
        printf("Canno't make file %s\n", info.filename);
        exit(EXIT_FAILURE);
    }

    // Used in case the last segment is smaller than the others
    i = 0;
    while (i < info.numberOfSegments - 1) {
        fwrite(segment[i].data, sizeof(char), info.lengthOfSegment, dest);
        i++;
    }

    i = 0;
    while (i != info.lengthOfLastSegment) {
        fputc(segment[info.numberOfSegments - 1].data[i], dest);
        i++;
    }
    fclose(dest);
}

void SortSegments(Segment *A, FileInfo X) {
    unsigned int i = 0;
    unsigned int j = i;
    Segment temp;
    for (i = 0; i < X.numberOfSegments - 1; i++)
        for (j = i; j < X.numberOfSegments; j++)
            if (A[j].segmentNumber < A[i].segmentNumber) {
                temp = A[j];
                A[j] = A[i];
                A[i] = temp;
            }
}

#endif //P_SEGMENTER_H
