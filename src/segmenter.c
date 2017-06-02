#include <segmenter.h>

char *ExtractFilename(const char *path)
{
    char *temp = NULL;
    int i = 0;
    int j = 0;
    int k = 0;
    while (path[i] != 0)
    {
        i++;
    }
    j = i - 1;
    while (path[j] != '/' && j >= 0)
    {
        j--;
    }
    j++;

    temp = (char *) malloc((i - j + 1) * sizeof(char));
    if (temp == NULL)
    {
        printf("Couldn't allocate memory for storing filename");
        exit(EXIT_FAILURE);
    }
    while (j != i)
    {
        temp[k] = path[j];
        j++;
        k++;
    }
    return temp;
}

void ClearBuffer(char *data, unsigned int N)
{
    unsigned int i;
    for (i = 0; i < N; i++)
    {
        data[i] = 0;
    }
}

void EraseFileInfo(FileInfo info) { free(info.fileName); }

void EraseSegmentInfo(Segment **segmentInfo, unsigned int numberOfSegments)
{
    unsigned int i = 0;
    for (i = 0; i < numberOfSegments; i++)
    {
        free((*segmentInfo)[i].data);
    }
    free(*segmentInfo);
}

FileInfo OpenAndDivide(unsigned int N, const char *path,
                       Segment **segment)
{

    unsigned int sizeOfFile = 0;
    unsigned int sizeOfSegment = 0;
    char byte = 0;
    unsigned int numberOfSegments = 1;
    char stream[N + 1];
    FILE *source = NULL;
    char *filename = NULL;
    FileInfo ret;

    source = fopen(path, "rb");
    if (source == NULL)
    {
        printf("Cant open %s\n", path);
        exit(EXIT_FAILURE);
    }
    rewind(source);
    filename = ExtractFilename(path);
    ret.fileName = filename;
    ret.lengthOfSegment = N;
    ClearBuffer(stream, N + 1);
    do
    {
        byte = (char) fgetc(source);
        if (feof(source))
            break;
        sizeOfFile++;
        stream[sizeOfSegment] = byte;

        if (N - 1 - sizeOfSegment == 0)
        {
            *segment =
                    (Segment *) realloc(*segment, sizeof(Segment) * numberOfSegments);
            if (*segment == NULL)
            {
                puts("Not enough memory for a segment");
                exit(EXIT_FAILURE);
            }

            (*segment)[numberOfSegments - 1].data =
                    (char *) malloc(ret.lengthOfSegment + 1);

            if ((*segment)[numberOfSegments - 1].data == NULL)
            {
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
    if (sizeOfFile == 0)
    {
        printf("Empty file or Premature EOF... aborting\n");
        exit(EXIT_FAILURE);
    }
    *segment = (Segment *) realloc(*segment, sizeof(Segment) * numberOfSegments);
    if (*segment == NULL)
    {
        puts("Not enough memory for allocating a segment");
        exit(EXIT_FAILURE);
    }
    (*segment)[numberOfSegments - 1].data =
            (char *) malloc(ret.lengthOfSegment + 1);
    if ((*segment)[numberOfSegments - 1].data == NULL)
    {
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

void PrintInfo(FileInfo info, Segment *segment)
{
    printf("\nPRINTING FILE INFORMATION\n\n");
    printf("FILENAME:                     %s\n", info.fileName);
    printf("NUMBER OF SEGMENTS            %u\n", info.numberOfSegments);
    printf("LENGTH OF A SEGMENT:          %u\n", info.lengthOfSegment);
    printf("LENGTH OF THE LAST SEGMENT:   %u\n\n", info.lengthOfLastSegment);

    printf("\nPRINTING SEGMENTS INFORMATION\n\n");
    unsigned int i = 0;
    for (i = 0; i < info.numberOfSegments; i++)
    {
        printf("SEGMENT NUMBER:                     %u\n",
               segment[i].segmentNumber);
        printf("DATA OF SEGMENT:                    %s\n\n", segment[i].data);
    }
}

void Reconstruct(FileInfo info, Segment segment[])
{
    FILE *dest = fopen(info.fileName, "wb");
    unsigned int i = 0;
    if (dest == NULL)
    {
        printf("Can't make file %s\n", info.fileName);
        exit(EXIT_FAILURE);
    }
    SortSegments(segment, info);
    i = 0;
    while (i < info.numberOfSegments - 1)
    {
        fwrite(segment[i].data, sizeof(char), info.lengthOfSegment, dest);
        i++;
    }

    i = 0;
    while (i != info.lengthOfLastSegment)
    {
        fputc(segment[info.numberOfSegments - 1].data[i], dest);
        i++;
    }
    fclose(dest);
}

void SortSegments(Segment *A, FileInfo X)
{
    unsigned int i = 0;
    unsigned int j;
    Segment temp;
    for (i = 0; i < X.numberOfSegments - 1; i++)
        for (j = i; j < X.numberOfSegments; j++)
            if (A[j].segmentNumber < A[i].segmentNumber)
            {
                temp = A[j];
                A[j] = A[i];
                A[i] = temp;
            }
}

void EraseData(Segment **segment, FileInfo info)
{
    EraseSegmentInfo(segment, info.numberOfSegments);
    EraseFileInfo(info);
}

unsigned ExtractFilenameLength(FileInfo info)
{
    unsigned i = 0;
    while (info.fileName[i] != '\0')
    {
        i++;
    }
    return i;
}