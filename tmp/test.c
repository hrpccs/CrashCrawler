#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#define NAMELIMIT 100
#define LISTLIMT 500000
const char *KALLPATH = "/proc/kallsyms";
// const char *KALLPATH = "./symbol";

typedef struct
{
    /*
        One node for symbol table
    */
    unsigned long int address;
    char flag;
    char name[NAMELIMIT];
    //    symbolNode(unsigned long int _addr = 0, char _flag = 0, _name = ""):
} symbolNode;

typedef struct
{
    /*
        The whole table
    */
    symbolNode nodeArray[LISTLIMT];
    int length;
} symbolList;
symbolList symList;

static int char2int(char c)
{
    if (c <= '9' && c >= '0')
        return c - '0';
    else
        return c - 'a' + 10;
}
static long int calIndex(int n)
{
    long int ans = 1;
    while (n--)
        ans *= 16;
    return ans;
}
static void initializeSym()
{
    FILE *fp = fopen(KALLPATH, "r");
    char *line = NULL;
    size_t len = 0;
    size_t readLength;
    symList.length = 0;
    while ((readLength = getline(&line, &len, fp)) != -1)
    {
        int mod = 0;
        for (int i = 0; i < readLength; i++)
        {
            // printf("%c",line[i]);
            if (line[i] == '\t' || line[i] == '\n')
                break;
            if (line[i] == ' ')
            {
                ++mod;
                continue;
            }
            if (mod == 0)
            {
                if (i == 0)
                    symList.nodeArray[symList.length].address = 0;
                symList.nodeArray[symList.length].address += calIndex(15 - i) * char2int(line[i]);
            }
            else if (mod == 1)
            {
                symList.nodeArray[symList.length].flag = line[i];
            }
            else
            {
                if (i == 19)
                    memset(symList.nodeArray[symList.length].name, 0, sizeof(symList.nodeArray[symList.length].name));
                symList.nodeArray[symList.length].name[i - 19] = line[i];
            }
        }
        // printf("%#lx %c %s\n", symList.nodeArray[symList.length].address,symList.nodeArray[symList.length].flag,symList.nodeArray[symList.length].name);
        ++symList.length;
    }
}
static int quiSymbol(long int query)
{
    int left = 0, right = symList.length;
    while (left < right)
    {
        int mid = (left + right) / 2;
        if(symList.nodeArray[mid].address >= query)
            right = mid;
        else
            left = mid + 1;
    }
    left = left > 0 ? --left : left;
    return left;
}
typedef struct
{
    char kernelInfo[NAMELIMIT];
    char CPUINFO[NAMELIMIT * 10];
}sysInfo;

void initializeSysInfo()
{
    /*
        硬件信息脚本
        https://blog.csdn.net/LvJzzZ/article/details/112029991
    */
    FILE * fp;
    char buffer[800];
    fp=popen("bash hardware.sh","r");
    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        void* ptr = fgets(buffer,sizeof(buffer),fp);
        if(ptr == NULL)
            break;
        printf("%s",buffer);
    }
    pclose(fp);
}
void test1()
{
    initializeSym();
    printf("Finished initializing...\n");
    unsigned long int query = 0;
    for (int i = 0; i < 1; i++)
    {
        scanf("%lx", &query);
        int left = quiSymbol(query);
        printf("%#lx %s+%#lx\n", symList.nodeArray[left].address,symList.nodeArray[left].name, query - symList.nodeArray[left].address);
    }
}
int main()
{
    // initializeSysInfo();
    struct tm *tm;
	char ts[64];
    char pathname[100] = "/var/log/crashlog";
    char filename[100] = "423_06-05_09:54:13";
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%m-%d_%H:%M:%S", tm);
    printf("%s",ts);
    mkdir(pathname,S_IRWXU);

    FILE* fp = fopen(filename,"w");
    fprintf(fp,"hello world\n");
    fclose(fp);
    return 0;
}
