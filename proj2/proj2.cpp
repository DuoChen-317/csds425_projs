#include <iostream>
#include <string>
#include <fstream>
#include <cstdint>
#include <arpa/inet.h> 
#include <ctime>  
#include <unistd.h>

using namespace std;

struct TraceRecord{
    uint32_t number_st;
    uint32_t fractioin_st;
    unsigned char iphdr[20];
};

struct ForwardingTable{
    uint32_t ip_address;
    uint16_t prefix_len;
    uint16_t interface;
};

void parse_trace(const string &filename){
    ifstream file(filename, ios::binary);
    if(!file){
        cerr << "Error opening file: " << filename << endl;
        return;
    }

    TraceRecord record;
    while(file.read(reinterpret_cast<char*>(&record), sizeof(record))){
        // conver from network byte order to host byte order
        uint32_t ts_host = ntohl(record.number_st);
        uint32_t frac_host = ntohl(record.fractioin_st);
        double timestamp = ts_host + frac_host / 1e6;
        
        // process the ip header
        // ttl
        unsigned char ttl = record.iphdr[8];

        // checksum
        uint16_t checksum = (record.iphdr[10] << 8) | record.iphdr[11];
        char checksum_result = (checksum == 1234) ? 'P' : 'F'; // checksum valid or not

        // src and dst ip
        unsigned char *src = record.iphdr + 12;
        unsigned char *dst = record.iphdr + 16;
        string src_ip = to_string(src[0]) + "." + to_string(src[1]) + "." + to_string(src[2]) + "." + to_string(src[3]);
        string dst_ip = to_string(dst[0]) + "." + to_string(dst[1]) + "." + to_string(dst[2]) + "." + to_string(dst[3]);

        // print the ouput
        cout << fixed << timestamp << " " << src_ip << " " << dst_ip << " "  << checksum_result << " " << (int)ttl << endl;
    }
}

void parse_table(const string &filename){
    ifstream file(filename);
    if(!file){
        cerr << "Error opening file: " << filename << endl;
        return;
    }
    ForwardingTable forwardingTable;
    while(file.read(reinterpret_cast<char*>(&forwardingTable),sizeof(forwardingTable))){
        // convert from network byte order to host byte order
        uint16_t prefix_host = ntohs(forwardingTable.prefix_len);
        uint16_t interface_host = ntohs(forwardingTable.interface);

        unsigned char *bytes = reinterpret_cast<unsigned char*>(&forwardingTable.ip_address);
        // print the output
        cout << (int)bytes[0] << "."
             << (int)bytes[1] << "."
             << (int)bytes[2] << "."
             << (int)bytes[3] << " " 
             << prefix_host << " "  
             << interface_host << endl;
    }
}

void simulation(){
    cout << "Simulation mode not implemented yet." << endl;
    return;
}

int error_exit(const string &msg) {
    cerr << "error: " << msg << endl;
    return 1;
 }


enum class Mode{
    NONE,
    PRINT_PACKAGE,
    FORWARD_TABLE,
    SIMULATION
};



int main(int argc, char* argv[]){
    Mode mode = Mode::NONE;
    string package_filename ;
    string table_filename ;

    auto set_mode = [&](Mode new_mode) {
    if (mode != Mode::NONE){
        cerr << "error: multiple modes specified" << endl;
        exit(1);
        } 
    mode = new_mode;
    return 0;
    };

    int opt;
        while ((opt = getopt(argc, argv, "prst:f:")) != -1) {
        switch (opt) {
            case 't':
                package_filename = optarg; break;
            case 'f':
                table_filename = optarg; break; 
            case 'p':
                set_mode(Mode::PRINT_PACKAGE); break;
            case 'r':
                set_mode(Mode::FORWARD_TABLE); break;
            case 's':
                set_mode(Mode::SIMULATION); break;
            default:
                return error_exit("unknown option");
        }
    }

    switch(mode){
        case Mode::PRINT_PACKAGE:
            if(package_filename.empty()){
                return error_exit("no package file specified -t <filename>");
            }
            parse_trace(package_filename);
            break;
        case Mode::FORWARD_TABLE:
            if(table_filename.empty()){
                return error_exit("no forwarding table file specified -f <filename>");
            }
            parse_table(table_filename);
            break;
        case Mode::SIMULATION:
            if(table_filename.empty() || package_filename.empty()){
                return error_exit("both files must be specified -f <filename> -t <filename>");
            }
            simulation();
            break;
        case Mode::NONE:
            return error_exit("no mode specified");
        default:
            return error_exit("unknown mode");
    }

    return 0;
}