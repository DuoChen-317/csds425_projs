#include <iostream>
#include <string>
#include <fstream>
#include <unistd.h> // for getopt
using namespace std;

#define ADDR_LEN 4

void printMode(const string &filename) {
    // Function implementation goes here
    ifstream file(filename, ios::binary);
    if (!file) {
        cout << "Error opening file: " << filename << endl;
        return;
    }

    unsigned char ip[ADDR_LEN];
    while(file.read(reinterpret_cast<char*>(ip), ADDR_LEN)) {
        cout << static_cast<int>(ip[0]) << "."
             << static_cast<int>(ip[1]) << "."
             << static_cast<int>(ip[2]) << "."
             << static_cast<int>(ip[3]) << endl;
    }
    file.close(); 
}

void summaryMode(const string &filename) {
    // Function implementation goes here
    ifstream file(filename, ios::binary);
    if (!file) {
        cout << "Unable to open the file: " << filename << endl;
        return;
    }

    int total_ips = 0;
    int private_ips = 0;

    unsigned char ip[ADDR_LEN];
    while(file.read(reinterpret_cast<char*>(ip), ADDR_LEN)) {
        total_ips++;
        if(ip[0] == 10) {
            // private IP
            private_ips++;
        }
    }

    cout << "total IPs: " << total_ips << endl;
    cout << "private IPs: " << private_ips << endl;
    file.close();
}


int main(int argc, char* argv[]) {
    // Command line argument parsing
    bool pMode = false; // true for print mode
    bool sMode = false; // true for summary mode
    string filename;

    int opt;
    while ((opt = getopt(argc, argv, "psr:")) != -1) {
        switch (opt) {
            case 'p':
                pMode = true; break;
            case 's':
                sMode = true; break;
            case 'r':
                filename = optarg; break;
            default:
                cerr << "error: unknown option: -" << (char)optopt<< endl;
                return 1;
        }
    }
    if(!sMode && !pMode) {
        cerr << "error: no mode given" << endl;
        return 1;
    }

    if(sMode && pMode) {
        cerr << "error: cannot use both -p and -s" << endl;
        return 1;
    }

    if(filename.empty()) {
        cerr << "error: no input file given" << endl;
        return 1;
    }

    if(pMode) {
        printMode(filename);
    } else if(sMode) {
        summaryMode(filename);
    }
    return 0;
}
    
