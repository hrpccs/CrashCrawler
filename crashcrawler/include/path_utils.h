#include <unordered_map>
#include <string>
#include <unistd.h>
#include <cstdio>
#include <cstring>


class PathUtils {
public:
    // can turn inode to path 
    PathUtils(){
        // map device number to /dev/* 
        // parse "lsblk -o NAME,MAJ:MIN" 
        FILE *fp = popen("lsblk -l -o NAME,MAJ:MIN", "r");
        if (fp == NULL) {
            printf("Failed to run command\n" );
            exit(1);
        }

        char dev_name[100];
        unsigned int major = 0;
        unsigned int minor = 0;

        // escape first line
        fscanf(fp, "%*[^\n]\n", NULL);

        while (fscanf(fp, "%s %u:%u", dev_name, &major, &minor) != EOF) {
            if (major == 0 || minor == 0) {
                continue;
            }
            std::string dev_path = "/dev/";
            dev_path += dev_name;
            dev_map[(major << 20) + minor] = dev_path;
        }
        pclose(fp);

        // test 
        for (auto it = dev_map.begin(); it != dev_map.end(); it++) {
            printf("%u %s\n", it->first, it->second.c_str());
        }
    }

    std::string get_dev_path(unsigned int dev){
        auto it = dev_map.find(dev);
        if (it == dev_map.end()) {
            return "";
        }
        return it->second;
    }

    std::string get_dev_path(unsigned int major, unsigned int minor) {
        return get_dev_path((major << 20) + minor);
    }

    std::string get_inode_path(unsigned int inode, unsigned int dev) {
        auto it = inode_map.find(inode);
        if (it == inode_map.end()) {
            char cmd[100];
            sprintf(cmd, "sudo debugfs -R \" ncheck %u\" %s 2> /dev/null |awk 'NR==2{print $1}NR==2{print $2}\'", inode, get_dev_path(dev).c_str());
            FILE *fp = popen(cmd, "r");
            if (fp == NULL) {
                printf("Failed to run command\n" );
                exit(1);
            }
            //print all output
            // char buf[100];
            // while (fgets(buf, 100, fp) != NULL) {
            //     printf("%s", buf);
            // }

            unsigned int inode1 = 0;
            char inode_buf[20];
            char inode_path[100];
            // read the 3th line
            if(fgets(inode_buf, 20, fp) == NULL){
                return "";
            }
            if(fgets(inode_path, 100, fp) == NULL){
                return "";
            }
            pclose(fp);

            inode_buf[strlen(inode_buf) - 1] = '\0';
            inode_path[strlen(inode_path) - 1] = '\0';

            if(inode_path[0] != '/'){
                return "";
            }
            inode_map[inode] = inode_path;
        }
        return inode_map[inode];
    }

    void set_inode_path(unsigned int inode, std::string path) {
        inode_map[inode] = path;
    }

private:
    std::unordered_map<unsigned int,std::string>  dev_map;
    std::unordered_map<unsigned int,std::string> inode_map;
};
