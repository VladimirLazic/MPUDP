#include <segmenter.h>

int main() {
    FileInfo file;
    Segment* segment = NULL;
    file = OpenAndDivide(5,"/home/niketic95/Documents/University/VI/ORM2/UDP-continuous-stream/files/FILE.data",&segment);
    PrintInfo(file,segment);
    Reconstruct(file,segment);
    return 0;
}