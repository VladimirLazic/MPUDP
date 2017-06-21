//
// Created by niketic95 on 23/05/17.
//

#ifndef P_SEGMENTER_H
#define P_SEGMENTER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @struct  Segment
 * @brief Single segment
 * A single segment contains its data and its segment number
 */
typedef struct segment
{
    char *data; /**< Data of segment segment_s#data*/
    unsigned int segmentNumber; /** <ID of segment segment_s#segmentNumber*/
} Segment;
/**
 * @struct  FileInfo
 * @brief File Information
 * Information about opened file. How many segments it contains what are their standard lengths and
 * the length of the last segment because it can be less than standard lengths
 */
typedef struct fileinfo
{
    char *fileName;/**< Name of the file */
    unsigned int numberOfSegments;/**<How many segments does the files have*/
    unsigned int lengthOfSegment;/**<How long are the standard segments*/
    unsigned int lengthOfLastSegment;/**<How long is the last segment*/
} FileInfo;

/**
 * @param path
 *  Absolute path to file
 * @return
 *  Filename
 */
char *ExtractFilename(const char *path);

/**
 * @param info
 *  Frees filename
 */
void EraseFileInfo(FileInfo info);

/**
 * @param segmentInfo
 *  Erase dynamic segment info
 * @param numberOfSegments
 *  How much to erase
 */
void EraseSegmentInfo(Segment **segmentInfo, unsigned int numberOfSegments);

/**
 * @param N
 *  Length of segments
 * @param path
 *  Path to file
 * @param segment
 *  Segment address to dump segment info in
 * @return
 *  Return file info
 */
FileInfo OpenAndDivide(unsigned int N, const char *path, Segment **segment);

/**
 * @param info
 *  Prints file info
 * @param segment
 *  Prints segment data
 */
void PrintInfo(FileInfo info, Segment *segment);

/**
 * @param info
 *  File Info
 * @param segment
 *  Segment array
 */
void Reconstruct(FileInfo info, Segment *segment);

/**
 * @param A
 *  Array of segments
 * @param X
 *  File info
 */
void SortSegments(Segment *A, FileInfo X);

/**
 * @param data
 *  Data in buffer to clear
 * @param N
 *  How much to clear
 */
void ClearBuffer(char *data, unsigned int N);

/**
 * @param segment
 *  Address of segment array
 * @param info
 *  FileInfo object
 */
void EraseData(Segment **segment, FileInfo info);

/**
 * @brief
 *  Extracts how long the filename is
 * @param info
 *  File to extract length
 * @return
 *  Returns how long the name is
 */
unsigned ExtractFilenameLength(FileInfo info);
#endif
