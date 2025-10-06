/*
 * Name: Duo Chewn
 * Case ID: dxc830
 * File: proj2.cpp
 * date: 2025-9-29
 * Description: C++ implementation of a simple router simulator.
 *              Supports three modes: package print, forwarding table display, and simulation.  
*/

#include <iostream>
#include <string>
#include <fstream>
#include <cstdint>
#include <arpa/inet.h> 
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <iomanip>
using namespace std;

// -----------------constants------------------------
const int DEFAULT_INTERFACE_ID = -1;
const uint32_t DEFAULT_IP = 0;
const uint16_t POLICY_INTERFACE = 0;

// -----------------datastructures------------------------
struct TraceRecord {
    uint32_t number_st;       // 4 bytes (seconds)
    uint32_t fraction_st;     // 4 bytes (microseconds)
    unsigned char iphdr[20];  
};

struct ParsedPacket {
    double timestamp;
    uint8_t ttl;
    bool checksum_ok;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct ForwardingTable_rule {
    uint32_t ip_address;
    uint16_t prefix_len;
    uint16_t interface;
};

enum class Mode {
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

string ip_to_string(uint32_t ip) {
    return to_string((ip >> 24) & 0xFF) + "." +
           to_string((ip >> 16) & 0xFF) + "." +
           to_string((ip >> 8) & 0xFF) + "." +
           to_string(ip & 0xFF);
}

vector<ForwardingTable_rule> parse_table(const string &filename) {
    vector<ForwardingTable_rule> forwarding_table;
    ifstream file(filename, ios::binary);
    if(!file) {
        cerr << "Error opening forwarding table file: " << filename << endl;
        return {};
    }

    ForwardingTable_rule rule;
    while(file.read(reinterpret_cast<char*>(&rule), sizeof(rule))) {
        rule.prefix_len = ntohs(rule.prefix_len);
        rule.interface  = ntohs(rule.interface);
        rule.ip_address = ntohl(rule.ip_address);
        forwarding_table.push_back(rule);
    }
    file.close();
    return forwarding_table;
}

// -----------------main API functions----------------------
void package_print_mode(const string &filename) {
    ifstream file(filename, ios::binary);
    if(!file) {
        cerr << "Error opening file: " << filename << endl;
        return;
    }

    TraceRecord record;
    cout << fixed << setprecision(6);
    while(file.read(reinterpret_cast<char*>(&record), sizeof(record))) {
        ParsedPacket packet;
        packet.timestamp   = ntohl(record.number_st) + ntohl(record.fraction_st) / 1e6;
        packet.ttl         = record.iphdr[8];
        packet.checksum_ok = (ntohs(*(uint16_t*)(record.iphdr + 10)) == 1234);
        packet.src_ip      = ntohl(*(uint32_t*)(record.iphdr + 12));
        packet.dst_ip      = ntohl(*(uint32_t*)(record.iphdr + 16));

        cout << packet.timestamp << " "
             << ip_to_string(packet.src_ip) << " "
             << ip_to_string(packet.dst_ip) << " "
             << (packet.checksum_ok ? "P" : "F") << " "
             << static_cast<int>(packet.ttl) << '\n';
    }
    file.close();
}

void forwarding_table_mode(const string &filename) {
    vector<ForwardingTable_rule> table = parse_table(filename);
    for(const auto& rule : table) {
        cout << ip_to_string(rule.ip_address) 
             << " " << rule.prefix_len
             << " " << rule.interface << '\n';
    }
}

void simulation_mode(const string &table_filename, const string &package_filename) {
    vector<ForwardingTable_rule> forwarding_table = parse_table(table_filename);
    if (forwarding_table.empty()) {
        cerr << "Forwarding table is empty or could not be loaded." << endl;
        return;
    }

    // ---------------- Duplicate prefix check ----------------
    for (size_t i = 0; i < forwarding_table.size(); ++i) {
        for (size_t j = i + 1; j < forwarding_table.size(); ++j) {
            if (forwarding_table[i].prefix_len == forwarding_table[j].prefix_len) {
                uint32_t mask = (forwarding_table[i].prefix_len == 0)
                                ? 0 : (~0u << (32 - forwarding_table[i].prefix_len));
                uint32_t masked1 = forwarding_table[i].ip_address & mask;
                uint32_t masked2 = forwarding_table[j].ip_address & mask;
                if (masked1 == masked2) {
                    cerr << "Error: duplicate prefix "
                        << ip_to_string(masked1) << "/" << forwarding_table[i].prefix_len << endl;
                    exit(1);
                }
            }
        }
    }

    // ---------------- Precompute masks ----------------
    uint32_t masks[33];
    for (int i = 0; i <= 32; ++i)
        masks[i] = (i == 0) ? 0 : (~0u << (32 - i));

    // ---------------- Build fast lookup table ----------------
    unordered_map<int, unordered_map<uint32_t, int>> fast_table; 
    int default_iface = -1;

    for (const auto& rule : forwarding_table) {
        uint32_t masked_ip = rule.ip_address & masks[rule.prefix_len];
        if (rule.ip_address == DEFAULT_IP)
            default_iface = rule.interface;
        fast_table[rule.prefix_len][masked_ip] = rule.interface;
    }

    // ---------------- Open packet trace ----------------
    ifstream file(package_filename, ios::binary);
    if (!file) {
        cerr << "Error opening trace file: " << package_filename << endl;
        return;
    }

    TraceRecord record;
    cout << fixed << setprecision(6);

    // ---------------- Process each packet ----------------
    while (file.read(reinterpret_cast<char*>(&record), sizeof(record))) {
        ParsedPacket packet;
        packet.timestamp   = ntohl(record.number_st) + ntohl(record.fraction_st) / 1e6;
        packet.ttl         = record.iphdr[8];
        packet.checksum_ok = (ntohs(*(uint16_t*)(record.iphdr + 10)) == 1234);
        packet.src_ip      = ntohl(*(uint32_t*)(record.iphdr + 12));
        packet.dst_ip      = ntohl(*(uint32_t*)(record.iphdr + 16));

        string action = "drop unknown";

        // checksum & TTL
        if (!packet.checksum_ok) {
            action = "drop checksum";
        } 
        else if (packet.ttl <= 1) {
            packet.ttl = 0;
            action = "drop expired";
        } 
        else {
            int best_iface = -1;
            // Longest-prefix search using hash lookup
            for (int len = 32; len >= 0; --len) {
                uint32_t masked_dst = packet.dst_ip & masks[len];
                auto outer = fast_table.find(len);
                if (outer == fast_table.end()) continue;

                auto inner = outer->second.find(masked_dst);
                if (inner != outer->second.end()) {
                    best_iface = inner->second;
                    break; // found the longest prefix match
                }
            }

            if (best_iface == POLICY_INTERFACE)
                action = "drop policy";
            else if (best_iface > POLICY_INTERFACE)
                action = "send " + to_string(best_iface);
            else if (default_iface != DEFAULT_INTERFACE_ID)
                action = "default " + to_string(default_iface);
        }

        cout << packet.timestamp << " " << action << '\n';
    }

    file.close();
}


// -----------------main----------------------
int main(int argc, char* argv[]) {
    Mode mode = Mode::NONE;
    string package_filename;
    string table_filename;

    auto set_mode = [&](Mode new_mode) {
        if(mode != Mode::NONE) {
            cerr << "error: multiple modes specified" << endl;
            exit(1);
        } 
        mode = new_mode;
        return 0;
    };

    int opt;
    while((opt = getopt(argc, argv, "prst:f:")) != -1) {
        switch(opt) {
            case 't': package_filename = optarg; break;
            case 'f': table_filename = optarg; break; 
            case 'p': set_mode(Mode::PRINT_PACKAGE); break;
            case 'r': set_mode(Mode::FORWARD_TABLE); break;
            case 's': set_mode(Mode::SIMULATION); break;
            default: return error_exit("unknown option");
        }
    }

    switch(mode) {
        case Mode::PRINT_PACKAGE:
            if(package_filename.empty())
                return error_exit("no package file specified -t <filename>");
            package_print_mode(package_filename);
            break;
        case Mode::FORWARD_TABLE:
            if(table_filename.empty())
                return error_exit("no forwarding table file specified -f <filename>");
            forwarding_table_mode(table_filename);
            break;
        case Mode::SIMULATION:
            if(table_filename.empty() || package_filename.empty())
                return error_exit("both files must be specified -f <table_filename> -t <package_filename>");
            simulation_mode(table_filename, package_filename);
            break;
        case Mode::NONE:
            return error_exit("no mode specified");
        default:
            return error_exit("unknown mode");
    }
    return 0;
}
