#include <iostream>
#include <string>
#include <fstream>
#include <cstdint>
#include <arpa/inet.h> 
#include <ctime>  
#include <unistd.h>

using namespace std;

// -----------------datastructures------------------------
struct TraceRecord {
    uint32_t number_st;       // 4 bytes (seconds)
    uint32_t fraction_st;     // 4 bytes (microseconds)
    unsigned char iphdr[20];  // 20 bytes (IPv4 header)
};

struct ParsedPacket {
    double timestamp;
    uint8_t ttl;
    bool checksum_ok;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct ForwardingTable_rule{
    uint32_t ip_address;
    uint16_t prefix_len;
    uint16_t interface;
};

enum class Mode{
    NONE,
    PRINT_PACKAGE,
    FORWARD_TABLE,
    SIMULATION
};

// -----------------helper functions---------------------------
int error_exit(const string &msg) {
    cerr << "error: " << msg << endl;
    return 1;
}

string ip_to_string(uint32_t ip){
    return to_string((ip >> 24) & 0xFF) + "." +
           to_string((ip >> 16) & 0xFF) + "." +
           to_string((ip >> 8) & 0xFF) + "." +
           to_string(ip & 0xFF);
}

vector<ParsedPacket> parse_trace(const string &filename){
    vector<ParsedPacket> packets;
    // read the binary file
    ifstream file(filename, ios::binary);
    if(!file){
        cerr << "Error opening file: " << filename << endl;
        return {};
    }

    TraceRecord record;
    while(file.read(reinterpret_cast<char*>(&record), sizeof(record))){
        ParsedPacket packet;
        packet.timestamp = ntohl(record.number_st) + ntohl(record.fraction_st) / 1e6;
        packet.ttl = record.iphdr[8];
        packet.checksum_ok = (ntohs(*(uint16_t*)(record.iphdr + 10)) == 1234);
        packet.src_ip = ntohl(*(uint32_t*)(record.iphdr + 12));
        packet.dst_ip = ntohl(*(uint32_t*)(record.iphdr + 16));
        packets.push_back(packet);
    }
    file.close();
    return packets;
}

vector<ForwardingTable_rule> parse_table(const string &filename){
    vector<ForwardingTable_rule> forwarding_table;
    // load forwarding table
    ifstream file(filename);
    if(!file){
        cerr << "Error opening forwarding table file: " << filename << endl;
        return {};
    }
    ForwardingTable_rule rule;
    while(file.read(reinterpret_cast<char*>(&rule),sizeof(rule))){
        // convert from network byte order to host byte order
        rule.prefix_len = ntohs(rule.prefix_len);
        rule.interface = ntohs(rule.interface);
        rule.ip_address = ntohl(rule.ip_address);

        forwarding_table.push_back(rule);
    }
    file.close();
    return forwarding_table;
}

// -----------------main AIP functions----------------------

void package_print_mode(const string &filename){
    vector<ParsedPacket> packets = parse_trace(filename);
    for(const auto& packet : packets){
        cout << fixed;
        cout.precision(6);
        cout << packet.timestamp << " "
             << ip_to_string(packet.src_ip) << " "
             << ip_to_string(packet.dst_ip) << " "
             << (packet.checksum_ok ? "P" : "F") << " "
             << static_cast<int>(packet.ttl)
             << endl;
    }
}

void forwarding_table_mode(const string &filename){
    vector<ForwardingTable_rule> table = parse_table(filename);
    for(const auto& rule : table){
        cout << ip_to_string(rule.ip_address) 
             << " " << rule.prefix_len
             << " " << rule.interface << endl;
    }
}

void simulation_mode(const string &table_filename, const string &package_filename){
    // the router forwarding table
    vector<ForwardingTable_rule> forwarding_table;
    forwarding_table = parse_table(table_filename);
    if(forwarding_table.empty()){
        cerr << "Forwarding table is empty or could not be loaded." << endl;
        return;
    }
    // check the duplicate entries in the forwarding table
    for(size_t i = 0; i < forwarding_table.size(); ++i){
        for(size_t j = i + 1; j < forwarding_table.size(); ++j){
            if(forwarding_table[i].ip_address == forwarding_table[j].ip_address &&
               forwarding_table[i].prefix_len == forwarding_table[j].prefix_len){
                cerr << "Warning: Duplicate entry in forwarding table for "
                     << ip_to_string(forwarding_table[i].ip_address)
                     << "/" << forwarding_table[i].prefix_len << endl;
            }
        }
    }
    // process the package file
    vector<ParsedPacket> packets = parse_trace(package_filename);
    for(auto& package : packets){
        string action = "drop unknown";
        // check checksum
        if(!package.checksum_ok){
            action = "drop checksum";
            }   

        // check TTL
        else if(package.ttl <= 1){
            action = "drop expired";
            }

        else {
            int longest_prefix = -1;
            const ForwardingTable_rule* best_rule = nullptr;
            // check the dst ip in the forwarding table
            for(const auto& rule : forwarding_table){
                uint32_t mask = (rule.prefix_len == 0) ? 0 : (~0u << (32 - rule.prefix_len));
                if((package.dst_ip & mask) == (rule.ip_address & mask)){
                    // find the longest prefix match
                    if(static_cast<int>(rule.prefix_len) > longest_prefix){
                        longest_prefix = rule.prefix_len;
                        best_rule = &rule;}
                    }
                }
            if(best_rule){
                // if matched, check the if the best_rule is drop rule
                if(best_rule->interface == 0){action = "drop policy";}
                else{action = "send " + to_string(best_rule->interface);}
            }else{
                // find the default route
                for(const auto& rule : forwarding_table){
                    if(rule.ip_address == 0){action = "default " + to_string(rule.interface);}
                    }
                }
            }
        cout << fixed << package.timestamp << " " << action << endl;
    }
}


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
            package_print_mode(package_filename);
            break;
        case Mode::FORWARD_TABLE:
            if(table_filename.empty()){
                return error_exit("no forwarding table file specified -f <filename>");
            }
            forwarding_table_mode(table_filename);
            break;
        case Mode::SIMULATION:
            if(table_filename.empty() || package_filename.empty()){
                return error_exit("both files must be specified -f <table_filename> -t <package_filename>");
            }
            simulation_mode(table_filename, package_filename);
            break;
        case Mode::NONE:
            return error_exit("no mode specified");
        default:
            return error_exit("unknown mode");
        }
    return 0;
}