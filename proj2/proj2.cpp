#include <iostream>
#include <string>
#include <fstream>
#include <cstdint>
#include <arpa/inet.h> 
#include <ctime>  

using namespace std;

void read_file(const string &filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cout << "Error opening file: " << filename << endl;
        return;
    }
    string line;
    uint32_t pacage;  // 4 bytes for IPv4
    while (file.read(reinterpret_cast<char*>(&pacage), sizeof(pacage))) {
        // Convert from network byte order (big endian) to host byte order
        uint32_t ts_host = ntohl(ts_raw);


    }

    file.close();
    
    file.close();

}

int main(){
    cout << "Hello World!" << endl;
    read_file("./test/ex1.trace");
    cout << "Goodbye!" << endl;
    return 0;
}